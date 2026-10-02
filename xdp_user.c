/**
 * @file xdp_user.c
 * @brief XDP用户态程序实现（300Mbps、64-128B小包加/解密转发优化版）
 *
 * 说明：以下仅“新增注释”，不改动你原本的任何代码逻辑/结构/变量名/宏定义/流程。
 *
 * 在你现有版本基础上补齐关键点：
 * 1) RX addr/offset 正确处理：extract_addr/offset；回填 FQ 只回填 base addr
 * 2) TX 不再 reserve==0 就整批 drop：加入 TX pending + 自适应降阶 reserve
 * 3) FQ flush 非阻塞 + 自适应降阶 reserve，减少 pending 积压
 *
 * 新增：
 * 4) 读取内核 AF_XDP/XDP socket 统计（SOL_XDP / XDP_STATISTICS），
 *    重点计数：rx_ring_full、rx_fill_ring_empty_descs、rx_dropped 等
 *
 * 新增（本次修改）：
 * 5) 4核机器绑核：每个队列对由一个双向工作线程处理，共4线程、4个CPU
 *    绑核策略：两张网卡的同队列 socket 固定由同一个CPU处理：
 *      queue0: IF0(q0)+IF1(q0) -> CPU0
 *      queue1: IF0(q1)+IF1(q1) -> CPU1
 *      queue2: IF0(q2)+IF1(q2) -> CPU2
 *      queue3: IF0(q3)+IF1(q3) -> CPU3
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <sched.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_xdp.h>   /* struct xdp_statistics, SOL_XDP, XDP_STATISTICS */

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include "sm4.h"
#include "sp_header.h"
#include "config.h"
#include "debug.h"

/** @name 框架配置常量 */
/**@{*/
/* UMEM 总帧数：一半用于 RX（FQ 回填），一半用于 TX（发包 buffer pool） */
#define NUM_FRAMES 8192
/* 单帧大小：必须 >= 最大包长（含 L2/L3/L4 + SPH + padding 等）并满足对齐要求 */
#define FRAME_SIZE 2048

/* 用户态一次处理/发送的批量大小（会影响 reserve/submit 频率与缓存局部性） */
#define BATCH_SIZE 32

/* ring 队列大小（libxdp/xsk 内部 ring 深度） */
#define RING_SIZE 4096
/* RX/TX 帧池划分：RX_FRAMES 为可用于 FQ 的帧数量；TX_FRAMES 为 TX pool 数量 */
#define RX_FRAMES (NUM_FRAMES / 2)
#define TX_FRAMES (NUM_FRAMES / 2)
/* 多队列数：与网卡 RSS/队列数一致（这里固定 4） */
#define NUM_QUEUES 4
/* 网卡接口数：双口（in/out） */
#define NUM_INTERFACES 2
/**@}*/

/* 空闲自旋上限：RX 无包时先短自旋，再 poll，再 nanosleep，降低 CPU 空转 */
#define IDLE_SPIN_MAX 4096
#define IDLE_NANOSLEEP_NS 10000  /* 10us */

/* FQ 单次 flush 的期望上限：建议与 BATCH_SIZE 同步，减少 all-or-nothing reserve 卡顿 */
#define FQ_CHUNK_MAX BATCH_SIZE

/* eBPF map 名称：内核 XDP 程序通过这些 map 找到各队列的 xsk fd */
#define XDP_MAP_IN  "xsks_map_in"
#define XDP_MAP_OUT "xsks_map_out"
#define XDP_POLICY_MAP "traffic_policy_map"
#define XDP_DEVMAP     "tx_port_map"

/* pending ring 使用掩码优化：要求长度为 2^n */
#if (RX_FRAMES & (RX_FRAMES - 1))
#error "RX_FRAMES must be power of two for pending ring mask optimization"
#endif
#define FQ_PENDING_MASK (RX_FRAMES - 1)

#if (TX_FRAMES & (TX_FRAMES - 1))
#error "TX_FRAMES must be power of two for tx pending ring mask optimization"
#endif
#define TX_PENDING_MASK (TX_FRAMES - 1)

/* -------------------------- CPU affinity (4核机器) --------------------------
 *  4 个双向队列工作线程（每线程处理两张网卡的同号队列）。
 * 固定使用 CPU0-CPU3（不去用更高 CPU号，避免你误配置 IRQ/脚本时写到不存在的CPU）。
 */
#define MAX_WORK_CPUS 4
static int g_cpu_cnt = 0;

/* 线程名：避免 snprintf 触发 -Wformat-truncation（pthread name 16B 含 '\0'） */
static const char *const g_tnames[MAX_WORK_CPUS] = {
    "xdpq0", "xdpq1", "xdpq2", "xdpq3"
};

/* 取在线 CPU 数，并限制最多使用 CPU0-CPU3 */
static int get_work_cpu_count(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n <= 0) n = 1;
    if (n > MAX_WORK_CPUS) n = MAX_WORK_CPUS;
    return (int)n;
}

/* queue -> cpu：4队列对应4核；两张卡同队列由一个线程处理 */
static int cpu_for_worker(int queue_id)
{
    int cpu_cnt = g_cpu_cnt;
    if (cpu_cnt <= 0) cpu_cnt = 1;
    /* q0->0 q1->1 q2->2 q3->3（若 cpu_cnt<4 则取模收敛） */
    int cpu = queue_id % cpu_cnt;
    if (cpu < 0) cpu = 0;
    if (cpu >= MAX_WORK_CPUS) cpu %= MAX_WORK_CPUS;
    return cpu;
}

/* 线程内再次“保险绑核”（即使创建线程时 attr 绑核失败，这里也会再绑一次） */
static void bind_current_thread_to_cpu(int cpu)
{
    if (cpu < 0) cpu = 0;
    if (cpu >= MAX_WORK_CPUS) cpu %= MAX_WORK_CPUS;

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);

    int ret = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    if (ret) {
        EPRINT("WARN: pthread_setaffinity_np(cpu=%d) failed: %s\n", cpu, strerror(ret));
        return;
    }

    /* 按 CPU 号设置线程名：方便 top/htop/perf 观察 */
    (void)pthread_setname_np(pthread_self(), g_tnames[cpu]);
}

static void print_thread_bind_plan(int cpu_cnt, const char *if0, const char *if1)
{
    printf("=== CPU 绑核计划（4核机器）===\n");
    printf("online_cpus(used)=%d, if0=%s, if1=%s\n", cpu_cnt, if0, if1);
    for (int q = 0; q < NUM_QUEUES; q++) {
        int cpu = (cpu_cnt > 0) ? (q % cpu_cnt) : 0;
        printf("  queue %d: (%s,q%d) + (%s,q%d) -> CPU%d\n", q, if0, q, if1, q, cpu);
    }
    printf("============================\n");
}

/* ----------------------------------------------------------------------- */

/* UMEM 相关：FQ/CQ ring、buffer 指针、RX/TX 分区起始地址 */
struct xsk_umem_info {
    struct xsk_ring_prod fq;    /* Fill Queue: 用户态 -> 内核，投递可写 RX buffer */
    struct xsk_ring_cons cq;    /* Completion Queue: 内核 -> 用户态，回收已发送 TX buffer */
    struct xsk_umem *umem;
    void *buffer;
    uint64_t rx_base_addr;      /* RX 分区起点（这里固定 0） */
    uint64_t tx_base_addr;      /* TX 分区起点（这里固定 RX_FRAMES*FRAME_SIZE） */
};

/* 统计：用户态自定义计数 + 内核 XDP_STATISTICS delta 累加 */
struct xsk_socket_stats {
    uint64_t rx_pkts;
    uint64_t tx_pkts;

    uint64_t drop_tx_ring_full;     /* 真实 drop：pending 溢出/无法承受 */
    uint64_t drop_tx_pool_empty;    /* TX buffer pool 用尽（通常表示 TX 侧拥塞/回收慢） */
    uint64_t drop_max_tx;           /* 单轮 rcvd > max_tx 时，超过可发预算的包被丢弃 */
    uint64_t drop_crypto_fail;      /* 加/解密处理失败（返回长度 0） */
    uint64_t len_mismatch;
    uint64_t suite_invalid;
    uint64_t key_lookup_fail;
    uint64_t seq_state_fail;
    uint64_t invalid_sph;

    uint64_t fq_wait_loops;         /* FQ reserve==0 时的等待/重试次数 */

    /* 语义：reserve 返回 0 的次数（现在可能多次降阶） */
    uint64_t tx_reserve_zero_retry; /* TX reserve==0 的重试次数 */
    uint64_t tx_partial_reserve;    /* TX reserve 得到的 ret != want 的次数 */

    uint64_t fq_pending_overflow;   /* FQ pending 环溢出（严重错误，当前直接退出） */

    /* ---- Kernel XDP/AF_XDP stats (SOL_XDP / XDP_STATISTICS) ---- */
    struct xdp_statistics xdp_last; /* 上次采样的内核统计快照 */
    bool xdp_last_valid;

    /* 累加“每秒 delta” */
    uint64_t k_rx_dropped;              /* 内核统计：RX 丢包（AF_XDP/xdp 层） */
    uint64_t k_rx_ring_full;            /* 内核统计：RX ring 满导致丢包 */
    uint64_t k_rx_fill_ring_empty_descs;/* 内核统计：FQ 空导致无法收包 */
    uint64_t k_rx_invalid_descs;
    uint64_t k_tx_invalid_descs;
};

/* 发送项：addr/len 组成一次 TX desc */
struct tx_item {
    uint64_t addr;
    uint32_t len;
};

/* 每个队列一个 socket info（这里一个线程处理一个 RX socket，并找到对应 TX socket） */
struct xsk_socket_info {
    struct xsk_ring_cons rx;   /* RX ring: 内核 -> 用户态，拿到 xdp_desc */
    struct xsk_ring_prod tx;   /* TX ring: 用户态 -> 内核，提交 xdp_desc */
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    int ifindex;
    int queue_id;

    unsigned int outstanding_tx; /* 已提交但尚未 CQ 回收的 TX 数量 */

    /* TX buffer pool：预分配的 TX 分区地址数组 + 计数 */
    uint64_t tx_addrs[TX_FRAMES];
    uint32_t tx_free_count;

    /* FQ pending ring: 非阻塞归还时的待提交地址队列（只放 base addr，不带 offset） */
    uint64_t fq_pending[RX_FRAMES];
    uint32_t fq_p_head;
    uint32_t fq_p_tail;
    uint32_t fq_p_cnt;

    /* TX pending ring: 当 TX ring 满/不足时，把已准备好的 tx_item 暂存，避免整批 drop */
    struct tx_item tx_pending[TX_FRAMES];
    uint32_t tx_p_head;
    uint32_t tx_p_tail;
    uint32_t tx_p_cnt;

    struct xsk_socket_stats st;
};

/* sockets[接口][队列]：双口四队列 => 8 个 socket */
static struct xsk_socket_info *sockets[NUM_INTERFACES][NUM_QUEUES] = { { NULL } };
/* 每个接口对应一个 xsks_map fd（内核通过 map[qid] = sockfd 找 AF_XDP socket） */
static int xsks_map_fds[NUM_INTERFACES] = { -1, -1 };
/* 主循环退出标志：SIGINT/SIGTERM 会置 0 */
static volatile sig_atomic_t keep_running = 1;

/* 小工具：min */
static inline uint32_t u32_min(uint32_t a, uint32_t b) { return a < b ? a : b; }

/* 单调时间（ns）：用于 1Hz 采样内核统计 */
static inline uint64_t nsec_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* 统计 delta：防止回绕时变负（这里简单做 cur>=prev 才累加） */
static inline uint64_t u64_delta(uint64_t cur, uint64_t prev)
{
    return (cur >= prev) ? (cur - prev) : 0;
}

/* 读取 AF_XDP socket 内核统计：SOL_XDP/XDP_STATISTICS */
static int xsk_read_xdp_stats(int fd, struct xdp_statistics *xs)
{
    socklen_t optlen = sizeof(*xs);
    memset(xs, 0, sizeof(*xs));
    if (getsockopt(fd, SOL_XDP, XDP_STATISTICS, xs, &optlen) < 0)
        return -1;
    return 0;
}

/* 从 TX pool 分配一个 TX frame addr（返回 1 成功 / 0 失败） */
static inline int tx_pool_alloc(struct xsk_socket_info *xsk, uint64_t *addr)
{
    if (xsk->tx_free_count == 0)
        return 0;
    xsk->tx_free_count--;
    *addr = xsk->tx_addrs[xsk->tx_free_count];
    return 1;
}

/* 归还 TX frame addr 到 pool（CQ 回收、或处理失败时释放） */
static inline void tx_pool_free(struct xsk_socket_info *xsk, uint64_t addr)
{
    if (xsk->tx_free_count < TX_FRAMES)
        xsk->tx_addrs[xsk->tx_free_count++] = addr;
}

static void signal_handler(int sig)
{
    (void)sig;
    keep_running = 0;
}

/* need_wakeup 模式下：当 prod ring 需要唤醒时，用 sendto/kick 通知内核 */
static inline void kick_if_needed(int fd, struct xsk_ring_prod *r)
{
    if (xsk_ring_prod__needs_wakeup(r)) {
        int sret = sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
        if (sret < 0 && errno != EAGAIN && errno != EBUSY) {
            DPRINT("kick failed: %s\n", strerror(errno));
        }
    }
}

/* 空闲等待：这里用 nanosleep(10us) 或 yield，避免纯自旋耗满 CPU */
static inline void idle_wait(void)
{
    if (IDLE_NANOSLEEP_NS > 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = IDLE_NANOSLEEP_NS;
        nanosleep(&ts, NULL);
    } else {
        sched_yield();
    }
}

/* -------------------------- UMEM / XSK init -------------------------- */

/* 创建 UMEM：对齐 buffer，建立 FQ/CQ ring，并预填充 RX_FRAMES 到 FQ */
static struct xsk_umem_info *xsk_configure_umem(void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem;
    int ret;

    if (!buffer || size < FRAME_SIZE) {
        EPRINT("Invalid buffer parameters\n");
        return NULL;
    }

    /* 确保 buffer 按 FRAME_SIZE 对齐（某些场景下提高访问效率/避免约束） */
    unsigned long addr = (unsigned long)buffer;
    if (addr % FRAME_SIZE != 0) {
        unsigned long aligned_addr = (addr + FRAME_SIZE - 1) & ~(FRAME_SIZE - 1);
        buffer = (void *)aligned_addr;
        size -= (aligned_addr - addr);
    }

    /* 确保对齐后仍然够 NUM_FRAMES*FRAME_SIZE */
    if (size < (uint64_t)NUM_FRAMES * FRAME_SIZE) {
        EPRINT("Buffer size too small after alignment: %lu (need %lu)\n",
               (unsigned long)size,
               (unsigned long)NUM_FRAMES * FRAME_SIZE);
        return NULL;
    }

    umem = calloc(1, sizeof(*umem));
    if (!umem) {
        EPRINT("Failed to allocate umem info\n");
        return NULL;
    }

    /* UMEM 配置：fill/comp ring 深度，frame_size，headroom（这里 0） */
    struct xsk_umem_config umem_cfg = {
        .fill_size = RING_SIZE,
        .comp_size = RING_SIZE,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
    };

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &umem_cfg);
    if (ret) {
        EPRINT("Failed to create umem: %s\n", strerror(-ret));
        free(umem);
        return NULL;
    }

    umem->buffer = buffer;

    /* RX 分区从 0 开始；TX 分区从 RX_FRAMES*FRAME_SIZE 开始 */
    umem->rx_base_addr = 0;
    umem->tx_base_addr = RX_FRAMES * FRAME_SIZE;

    if (umem->tx_base_addr % FRAME_SIZE != 0) {
        EPRINT("TX base address not aligned\n");
        xsk_umem__delete(umem->umem);
        free(umem);
        return NULL;
    }

    /* 预先一次性把 RX_FRAMES 全部投进 FQ：内核收包时从 FQ 取可写 buffer */
    uint32_t idx = 0;
    ret = xsk_ring_prod__reserve(&umem->fq, RX_FRAMES, &idx);
    if (ret != RX_FRAMES) {
        EPRINT("Failed to reserve fill queue\n");
        xsk_umem__delete(umem->umem);
        free(umem);
        return NULL;
    }

    for (int i = 0; i < RX_FRAMES; i++) {
        uint64_t frame_addr = umem->rx_base_addr + (uint64_t)i * FRAME_SIZE;
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) = frame_addr;
    }
    xsk_ring_prod__submit(&umem->fq, RX_FRAMES);

    return umem;
}

/* 创建 XSK：绑定某 ifname+queue_id，关联同 UMEM，得到 rx/tx rings */
static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem,
                                                    const char *ifname,
                                                    int ifindex,
                                                    int queue_id)
{
    struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info)
        return NULL;

    /* socket 配置：
     * - rx_size/tx_size: ring 深度
     * - INHIBIT_PROG_LOAD: 不让 libbpf 自动加载 xdp（你自己 load/attach）
     * - xdp_flags: drv mode
     * - bind_flags: NEED_WAKEUP + COPY（这里强制 copy）
     */
    struct xsk_socket_config cfg = {
        .rx_size = RX_FRAMES,
        .tx_size = TX_FRAMES,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_USE_NEED_WAKEUP |
                      (g_config.data_plane.zero_copy ? XDP_ZEROCOPY : XDP_COPY),
    };

    int ret = xsk_socket__create(&xsk_info->xsk, ifname, queue_id,
                                 umem->umem, &xsk_info->rx, &xsk_info->tx, &cfg);
    if (ret) {
        EPRINT("Failed to create socket: %s\n", strerror(-ret));
        free(xsk_info);
        return NULL;
    }

    xsk_info->umem = umem;
    xsk_info->ifindex = ifindex;
    xsk_info->queue_id = queue_id;
    xsk_info->outstanding_tx = 0;

    /* 初始化 TX pool：把 TX 分区的每个 frame addr 放入 free 列表 */
    for (int i = 0; i < TX_FRAMES; i++)
        xsk_info->tx_addrs[i] = umem->tx_base_addr + (uint64_t)i * FRAME_SIZE;
    xsk_info->tx_free_count = TX_FRAMES;

    /* 初始化 pending ring 指针 */
    xsk_info->fq_p_head = xsk_info->fq_p_tail = xsk_info->fq_p_cnt = 0;
    xsk_info->tx_p_head = xsk_info->tx_p_tail = xsk_info->tx_p_cnt = 0;

    /* 内核统计尚未采样 */
    xsk_info->st.xdp_last_valid = false;

    return xsk_info;
}

/* -------------------------- TX completion -------------------------- */

/* 从 CQ 回收已完成发送的 TX frame addr，并归还到 tx_pool */
static void complete_tx(struct xsk_socket_info *xsk)
{
    unsigned int completed;
    uint32_t idx_cq;

    while ((completed = xsk_ring_cons__peek(&xsk->umem->cq, TX_FRAMES, &idx_cq)) > 0) {
        for (unsigned int i = 0; i < completed; i++) {
            uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq + i);
            tx_pool_free(xsk, addr);
        }
        xsk_ring_cons__release(&xsk->umem->cq, completed);

        /* outstanding_tx 与 CQ 回收对应，避免 tx_room 计算失真 */
        if (xsk->outstanding_tx >= completed)
            xsk->outstanding_tx -= completed;
        else
            xsk->outstanding_tx = 0;
    }
}

/* -------------------------- FQ pending -------------------------- */

/* 将一批 RX base addr 放入 FQ pending（后续非阻塞 flush 到 FQ） */
static inline void fq_pending_push_batch(struct xsk_socket_info *xsk_rx,
                                         const uint64_t *addrs, uint32_t cnt)
{
    if (cnt == 0)
        return;

    /* FQ pending 环溢出：意味着 FQ 长期 reserve 不到，且 pending 未能及时 flush（严重） */
    if (xsk_rx->fq_p_cnt + cnt > RX_FRAMES) {
        xsk_rx->st.fq_pending_overflow++;
        EPRINT("FQ pending overflow (cnt=%u pending=%u)\n", cnt, xsk_rx->fq_p_cnt);
        keep_running = 0;
        return;
    }

    for (uint32_t i = 0; i < cnt; i++) {
        xsk_rx->fq_pending[xsk_rx->fq_p_tail] = addrs[i];
        xsk_rx->fq_p_tail = (xsk_rx->fq_p_tail + 1) & FQ_PENDING_MASK;
        xsk_rx->fq_p_cnt++;
    }
}

/* 非阻塞 flush：从 fq_pending 取地址，reserve FQ；reserve==0 时自适应 want>>=1 */
static void fq_flush_pending_nonblock(struct xsk_socket_info *xsk_rx, int rx_fd)
{
    uint32_t submitted_total = 0;

    while (xsk_rx->fq_p_cnt && keep_running) {
        /* want0：本轮最多提交 FQ_CHUNK_MAX，避免一次性 reserve 太大卡住 */
        uint32_t want0 = u32_min(xsk_rx->fq_p_cnt, (uint32_t)FQ_CHUNK_MAX);
        uint32_t want = want0;
        uint32_t idx_fq = 0;
        int ret = 0;

        /* 自适应降阶：FQ reserve 若拿不到，就把 want 折半直到 1 */
        while (want > 0) {
            ret = xsk_ring_prod__reserve(&xsk_rx->umem->fq, want, &idx_fq);
            if (ret < 0) {
                EPRINT("ERROR: FQ reserve failed: %s\n", strerror(-ret));
                keep_running = 0;
                return;
            }
            if (ret == 0) {
                xsk_rx->st.fq_wait_loops++;
                kick_if_needed(rx_fd, &xsk_rx->umem->fq);
                if (want == 1)
                    return;
                want >>= 1;
                continue;
            }
            break;
        }

        if (ret <= 0)
            break;

        /* 把 pending 的 base addr 填回 FQ（注意：这里只回填 base addr，不含 offset） */
        for (int i = 0; i < ret; i++) {
            uint64_t a = xsk_rx->fq_pending[xsk_rx->fq_p_head];
            xsk_rx->fq_p_head = (xsk_rx->fq_p_head + 1) & FQ_PENDING_MASK;
            xsk_rx->fq_p_cnt--;
            *xsk_ring_prod__fill_addr(&xsk_rx->umem->fq, idx_fq + i) = a;
        }

        xsk_ring_prod__submit(&xsk_rx->umem->fq, (uint32_t)ret);
        submitted_total += (uint32_t)ret;
    }

    /* need_wakeup 模式下：提交后可能需要 kick 内核 */
    if (submitted_total)
        kick_if_needed(rx_fd, &xsk_rx->umem->fq);
}

/* -------------------------- TX pending helpers -------------------------- */

/* 判断 tx_pending 环是否还能塞下 cnt 个 item */
static inline bool tx_pending_can_push(const struct xsk_socket_info *xsk_tx, uint32_t cnt)
{
    return (xsk_tx->tx_p_cnt + cnt <= TX_FRAMES);
}

/* 把未能立即送出的 items 推入 tx_pending；若 pending 满则视为真实 drop 并释放 TX buffer */
static inline void tx_pending_push_items(struct xsk_socket_info *xsk_rx_stats_owner,
                                         struct xsk_socket_info *xsk_tx,
                                         const struct tx_item *items,
                                         uint32_t cnt)
{
    if (cnt == 0)
        return;

    /* pending 满：说明 TX 长期拥塞，无法缓存更多；这里计入 drop_tx_ring_full */
    if (!tx_pending_can_push(xsk_tx, cnt)) {
        xsk_rx_stats_owner->st.drop_tx_ring_full += cnt;
        for (uint32_t i = 0; i < cnt; i++)
            tx_pool_free(xsk_tx, items[i].addr);
        return;
    }

    for (uint32_t i = 0; i < cnt; i++) {
        xsk_tx->tx_pending[xsk_tx->tx_p_tail] = items[i];
        xsk_tx->tx_p_tail = (xsk_tx->tx_p_tail + 1) & TX_PENDING_MASK;
        xsk_tx->tx_p_cnt++;
    }
}

/* 自适应 TX reserve：want -> reserve；ret==0 时 complete_tx + kick，再 want>>=1 */
static int tx_reserve_adaptive(struct xsk_socket_info *xsk_rx_stats_owner,
                               struct xsk_socket_info *xsk_tx,
                               int tx_fd,
                               uint32_t want,
                               uint32_t *idx_tx_out)
{
    while (want > 0) {
        uint32_t idx_tx = 0;
        int ret = xsk_ring_prod__reserve(&xsk_tx->tx, want, &idx_tx);
        if (ret < 0)
            return ret;

        if (ret == 0) {
            /* reserve==0：不是直接 drop，而是做回收/唤醒并降阶重试 */
            xsk_rx_stats_owner->st.tx_reserve_zero_retry++;
            complete_tx(xsk_tx);
            kick_if_needed(tx_fd, &xsk_tx->tx);

            if (want == 1)
                return 0;
            want >>= 1;
            continue;
        }

        *idx_tx_out = idx_tx;
        if (ret != (int)want)
            xsk_rx_stats_owner->st.tx_partial_reserve++;
        return ret;
    }
    return 0;
}

/* 将 items 写入 TX ring 并 submit（最多发送 ret 个，ret 由自适应 reserve 决定） */
static uint32_t tx_send_items_adaptive(struct xsk_socket_info *xsk_rx_stats_owner,
                                       struct xsk_socket_info *xsk_tx,
                                       int tx_fd,
                                       const struct tx_item *items,
                                       uint32_t cnt)
{
    if (cnt == 0)
        return 0;

    uint32_t idx_tx = 0;
    int ret = tx_reserve_adaptive(xsk_rx_stats_owner, xsk_tx, tx_fd, cnt, &idx_tx);
    if (ret <= 0)
        return 0;

    uint32_t n = (uint32_t)ret;
    for (uint32_t i = 0; i < n; i++) {
        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk_tx->tx, idx_tx + i);
        tx_desc->addr = items[i].addr;
        tx_desc->len  = items[i].len;
    }

    xsk_ring_prod__submit(&xsk_tx->tx, n);
    xsk_tx->outstanding_tx += n;
    xsk_rx_stats_owner->st.tx_pkts += n;

    kick_if_needed(tx_fd, &xsk_tx->tx);
    return n;
}

/* 非阻塞刷 tx_pending：每次取连续段（避免跨环拼接），发送不动就 break */
static void tx_flush_pending_nonblock(struct xsk_socket_info *xsk_rx_stats_owner,
                                      struct xsk_socket_info *xsk_tx,
                                      int tx_fd)
{
    while (xsk_tx->tx_p_cnt && keep_running) {
        uint32_t head = xsk_tx->tx_p_head;
        uint32_t avail = xsk_tx->tx_p_cnt;
        uint32_t want = u32_min(avail, (uint32_t)BATCH_SIZE);

        /* 只取一段连续空间，避免一次 memcpy/拼接处理 */
        uint32_t cont = TX_FRAMES - head;
        if (want > cont)
            want = cont;

        uint32_t sent = tx_send_items_adaptive(xsk_rx_stats_owner, xsk_tx, tx_fd,
                                               &xsk_tx->tx_pending[head], want);
        if (sent == 0)
            break;

        xsk_tx->tx_p_head = (xsk_tx->tx_p_head + sent) & TX_PENDING_MASK;
        xsk_tx->tx_p_cnt -= sent;

        /* 发送后及时回收 CQ，提高 tx_free_count，避免 TX pool 空 */
        complete_tx(xsk_tx);
    }
}

/* -------------------------- packet processor -------------------------- */

/* 每线程：绑定一个 RX socket（某接口某队列），并找到对端接口同队列的 TX socket */
#if 0 /* superseded by the one-thread-per-queue worker below */
static void *packet_processor(void *arg)
{
    struct xsk_socket_info *xsk = (struct xsk_socket_info *)arg;  /* RX socket */
    struct xsk_socket_info *xsk_tx = NULL;                        /* TX socket */

    /* Superseded worker: kept disabled below for historical reference only. */
    int cpu = cpu_for_worker(xsk->queue_id);
    bind_current_thread_to_cpu(cpu);

    uint32_t idx_rx = 0;
    struct pollfd fds[1];

    int target_iface;
    bool is_encrypt_mode = false;

    /* 根据当前 socket 的 ifindex 判断方向：
     * - IF_IN_INDEX：入方向 => 加密 => 发到对端接口（iface=1）
     * - IF_OUT_INDEX：出方向 => 解密 => 发回入接口（iface=0）
     */
    if (xsk->ifindex == IF_IN_INDEX) {
        target_iface = 1;
        is_encrypt_mode = true;
    } else if (xsk->ifindex == IF_OUT_INDEX) {
        target_iface = 0;
        is_encrypt_mode = false;
    } else {
        EPRINT("ERROR: Invalid interface index %d\n", xsk->ifindex);
        keep_running = 0;
        return NULL;
    }

    /* 同队列号对端 socket：用于 TX */
    xsk_tx = sockets[target_iface][xsk->queue_id];
    if (!xsk_tx) {
        EPRINT("ERROR: Could not find target socket for queue %d\n", xsk->queue_id);
        keep_running = 0;
        return NULL;
    }

    /* poll 用于 need_wakeup 模式下的低成本等待（这里 timeout=0 配合自旋/睡眠） */
    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(xsk->xsk);
    fds[0].events = POLLIN;

    const int rx_fd = xsk_socket__fd(xsk->xsk);
    const int tx_fd = xsk_socket__fd(xsk_tx->xsk);

    /* 一轮处理的临时数组：tx_items 为待发送描述；rx_addrs 为待回填 FQ 的 RX base addr */
    struct tx_item tx_items[BATCH_SIZE];
    uint64_t rx_addrs[BATCH_SIZE];

    uint64_t last_kstat_ts = nsec_now();

    while (keep_running) {
        /* 先尽量把 pending 的 RX buffer 回填到 FQ，避免内核因 FQ 空而丢包 */
        fq_flush_pending_nonblock(xsk, rx_fd);

        /* 先回收 TX 完成，提升 tx_free_count */
        complete_tx(xsk_tx);
        /* 再刷掉 tx_pending，尽量清空积压 */
        tx_flush_pending_nonblock(xsk, xsk_tx, tx_fd);

        /* 用 TX buffer 预算决定本次最多收多少（避免 RX 收太多却无 TX buffer） */
        uint32_t rx_budget = xsk_tx->tx_free_count;
        if (rx_budget > BATCH_SIZE) rx_budget = BATCH_SIZE;

        /* 没 TX buffer 就别 peek，先去推 pending / 等待 */
        if (rx_budget == 0) {
            // 可以选择：poll/idle_wait/只做 flush/complete
            idle_wait();
            continue;
        }

        /* 从 RX ring 取包（最多 rx_budget） */
        unsigned int rcvd = xsk_ring_cons__peek(&xsk->rx, rx_budget, &idx_rx);
        if (!rcvd) {
            /* 先短自旋：期间继续回收/flush，提高“有包时”的整体吞吐 */
            int spins = 0;
            for (; spins < IDLE_SPIN_MAX && keep_running; spins++) {
                complete_tx(xsk_tx);
                tx_flush_pending_nonblock(xsk, xsk_tx, tx_fd);

                rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
                if (rcvd)
                    break;
            }
            if (!rcvd) {
                /* 自旋无包：poll(0) 触发内核路径/减少空转，然后再 peek */
                (void)poll(fds, 1, 0);
                rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
                if (!rcvd) {
                    idle_wait();
                    continue;
                }
            }
        }

        xsk->st.rx_pkts += rcvd;

        /* 再次回收：给后续 max_tx 预算留更准确的 tx_free_count */
        complete_tx(xsk_tx);

        /* max_tx：受 TX pool 与 outstanding_tx（tx_room）双重约束 */
        unsigned int max_tx = xsk_tx->tx_free_count;
        unsigned int tx_room = (TX_FRAMES - xsk_tx->outstanding_tx);
        if (max_tx > tx_room)
            max_tx = tx_room;

        unsigned int prepared = 0;

        for (unsigned int i = 0; i < rcvd; i++) {
            const struct xdp_desc *rx_desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i);

            /* 关键点 1：正确处理 addr/offset
             * - rx_desc->addr 低位可能带 offset（headroom/分片等）
             * - extract_addr 得到 frame base addr（用于回填 FQ）
             * - extract_offset 得到偏移（用于取真实数据指针）
             */
            uint64_t rx_desc_addr = rx_desc->addr;
            uint64_t rx_base = xsk_umem__extract_addr(rx_desc_addr);
            uint64_t rx_off  = xsk_umem__extract_offset(rx_desc_addr);
            uint32_t len = rx_desc->len;

            /* 回填 FQ 只回填 base addr（不带 offset） */
            rx_addrs[i] = rx_base;

            /* 若本轮可发预算用尽：此包无法准备 TX，计入 drop_max_tx（但 RX buffer 仍会回填） */
            if (prepared >= max_tx) {
                xsk->st.drop_max_tx++;
                continue;
            }

            /* 从 TX pool 取一个 TX frame addr，用于输出密文/明文 */
            uint64_t tx_addr;
            if (!tx_pool_alloc(xsk_tx, &tx_addr)) {
                /* TX pool 空：后续也没法继续准备，更新 max_tx 并计数 */
                xsk->st.drop_tx_pool_empty++;
                max_tx = prepared;
                continue;
            }

            /* 通过 UMEM 基址 + (base+offset) 得到 RX 数据指针；TX 数据指针用 tx_addr（无 offset） */
            void *rx_data = xsk_umem__get_data(xsk->umem->buffer, rx_base + rx_off);
            void *tx_data = xsk_umem__get_data(xsk_tx->umem->buffer, tx_addr);

            uint32_t processed_len = 0;
            
            /* 加密/解密：返回处理后的长度（0 表示失败） */
            if (is_encrypt_mode)
                processed_len = packet_encrypt(rx_data, len, tx_data);
            else
                processed_len = packet_decrypt(rx_data, len, tx_data);

            if (processed_len == 0) {
                /* 处理失败：释放 TX buffer，计入 drop_crypto_fail */
                xsk->st.drop_crypto_fail++;
                switch (sp_last_error()) {
                    case SP_ERROR_INVALID_SPH: xsk->st.invalid_sph++; break;
                    case SP_ERROR_LENGTH_MISMATCH: xsk->st.len_mismatch++; break;
                    case SP_ERROR_SUITE_INVALID: xsk->st.suite_invalid++; break;
                    case SP_ERROR_KEY_LOOKUP_FAIL: xsk->st.key_lookup_fail++; break;
                    case SP_ERROR_SEQUENCE_STATE: xsk->st.seq_state_fail++; break;
                    default: break;
                }
                tx_pool_free(xsk_tx, tx_addr);
                continue;
            }
               
            //memcpy(tx_data, rx_data, len);
           // processed_len = len;

            /* 填充本轮待发送 tx_items */
            tx_items[prepared].addr = tx_addr;
            tx_items[prepared].len  = processed_len;
            prepared++;
        }

        /* 释放 RX ring 消费的描述符 */
        xsk_ring_cons__release(&xsk->rx, rcvd);

        /* 把 RX base addr 放到 FQ pending，并尽快 flush 回填，减少 rx_fill_ring_empty_descs */
        fq_pending_push_batch(xsk, rx_addrs, (uint32_t)rcvd);
        fq_flush_pending_nonblock(xsk, rx_fd);

        if (prepared) {
            /* 关键点 2：TX 自适应 reserve（不再 reserve==0 就整批 drop） */
            uint32_t sent = tx_send_items_adaptive(xsk, xsk_tx, tx_fd, tx_items, prepared);
            if (sent < prepared) {
                /* 未发送部分推入 tx_pending，等待后续 flush */
                tx_pending_push_items(xsk, xsk_tx, &tx_items[sent], prepared - sent);
            }
            /* 及时回收与 flush，减少 pending 积压 */
            complete_tx(xsk_tx);
            tx_flush_pending_nonblock(xsk, xsk_tx, tx_fd);
        }

        /* ---- kernel XDP statistics sampling (1 Hz) ----
         * 每秒采样一次 rx_fd 的内核统计，并按 delta 累加到 k_* 里。
         * 这些指标可用于定位：
         * - rx_ring_full：RX ring 满（用户态消费慢/调度不足）
         * - rx_fill_ring_empty_descs：FQ 空（用户态回填慢/卡住）
         * - rx_dropped：综合丢包
         */
        uint64_t now = nsec_now();
        if (now - last_kstat_ts >= 1000000000ull) {
            struct xdp_statistics xs;
            if (xsk_read_xdp_stats(rx_fd, &xs) == 0) {
                if (xsk->st.xdp_last_valid) {
                    xsk->st.k_rx_dropped +=
                        u64_delta(xs.rx_dropped, xsk->st.xdp_last.rx_dropped);
                    xsk->st.k_rx_ring_full +=
                        u64_delta(xs.rx_ring_full, xsk->st.xdp_last.rx_ring_full);
                    xsk->st.k_rx_fill_ring_empty_descs +=
                        u64_delta(xs.rx_fill_ring_empty_descs,
                                  xsk->st.xdp_last.rx_fill_ring_empty_descs);
                    xsk->st.k_rx_invalid_descs +=
                        u64_delta(xs.rx_invalid_descs, xsk->st.xdp_last.rx_invalid_descs);
                    xsk->st.k_tx_invalid_descs +=
                        u64_delta(xs.tx_invalid_descs, xsk->st.xdp_last.tx_invalid_descs);
                }
                xsk->st.xdp_last = xs;
                xsk->st.xdp_last_valid = true;
            }
            last_kstat_ts = now;
        }
    }

    /* 线程退出时打印一次统计快照（便于定位哪队列哪方向出问题） */
    printf("[ifindex=%d queue=%d mode=%s] rx=%lu tx=%lu "
           "drop{max_tx=%lu pool_empty=%lu tx_full=%lu crypto_fail=%lu} "
           "sp_error{invalid_sph=%lu len_mismatch=%lu suite_invalid=%lu key_lookup_fail=%lu seq_state=%lu} "
           "fq_wait_loops=%lu tx_zero_retry=%lu tx_partial=%lu fq_pending_overflow=%lu "
           "pending_cnt=%u tx_pending_cnt=%u "
           "kstat{rx_drop=%lu rx_ring_full=%lu rx_fill_empty_descs=%lu rx_inv=%lu tx_inv=%lu} "
           "kstat_last{rx_drop=%llu rx_ring_full=%llu rx_fill_empty_descs=%llu} cpu=%d\n",
           xsk->ifindex, xsk->queue_id, is_encrypt_mode ? "enc" : "dec",
           (unsigned long)xsk->st.rx_pkts,
           (unsigned long)xsk->st.tx_pkts,
           (unsigned long)xsk->st.drop_max_tx,
           (unsigned long)xsk->st.drop_tx_pool_empty,
           (unsigned long)xsk->st.drop_tx_ring_full,
           (unsigned long)xsk->st.drop_crypto_fail,
           (unsigned long)xsk->st.invalid_sph,
           (unsigned long)xsk->st.len_mismatch,
           (unsigned long)xsk->st.suite_invalid,
           (unsigned long)xsk->st.key_lookup_fail,
           (unsigned long)xsk->st.seq_state_fail,
           (unsigned long)xsk->st.fq_wait_loops,
           (unsigned long)xsk->st.tx_reserve_zero_retry,
           (unsigned long)xsk->st.tx_partial_reserve,
           (unsigned long)xsk->st.fq_pending_overflow,
           xsk->fq_p_cnt,
           xsk_tx ? xsk_tx->tx_p_cnt : 0,
           (unsigned long)xsk->st.k_rx_dropped,
           (unsigned long)xsk->st.k_rx_ring_full,
           (unsigned long)xsk->st.k_rx_fill_ring_empty_descs,
           (unsigned long)xsk->st.k_rx_invalid_descs,
           (unsigned long)xsk->st.k_tx_invalid_descs,
           (unsigned long long)(xsk->st.xdp_last_valid ? xsk->st.xdp_last.rx_dropped : 0),
           (unsigned long long)(xsk->st.xdp_last_valid ? xsk->st.xdp_last.rx_ring_full : 0),
           (unsigned long long)(xsk->st.xdp_last_valid ? xsk->st.xdp_last.rx_fill_ring_empty_descs : 0),
           cpu);

    return NULL;
}
#endif

struct queue_worker_arg {
    int queue_id;
};

static void account_sp_error(struct xsk_socket_info *xsk)
{
    xsk->st.drop_crypto_fail++;
    switch (sp_last_error()) {
        case SP_ERROR_INVALID_SPH: xsk->st.invalid_sph++; break;
        case SP_ERROR_LENGTH_MISMATCH: xsk->st.len_mismatch++; break;
        case SP_ERROR_SUITE_INVALID: xsk->st.suite_invalid++; break;
        case SP_ERROR_KEY_LOOKUP_FAIL: xsk->st.key_lookup_fail++; break;
        case SP_ERROR_SEQUENCE_STATE: xsk->st.seq_state_fail++; break;
        default: break;
    }
}

static bool process_socket_batch(struct xsk_socket_info *xsk,
                                 struct xsk_socket_info *xsk_tx,
                                 bool encrypt_mode,
                                 uint64_t *last_kstat_ts)
{
    const int rx_fd = xsk_socket__fd(xsk->xsk);
    const int tx_fd = xsk_socket__fd(xsk_tx->xsk);
    uint32_t idx_rx = 0;

    fq_flush_pending_nonblock(xsk, rx_fd);
    complete_tx(xsk_tx);
    tx_flush_pending_nonblock(xsk, xsk_tx, tx_fd);

    uint32_t budget = u32_min(xsk_tx->tx_free_count, (uint32_t)BATCH_SIZE);
    if (!budget) return false;
    unsigned int rcvd = xsk_ring_cons__peek(&xsk->rx, budget, &idx_rx);
    if (!rcvd) return false;
    xsk->st.rx_pkts += rcvd;

    complete_tx(xsk_tx);
    unsigned int max_tx = xsk_tx->tx_free_count;
    unsigned int tx_room = TX_FRAMES - xsk_tx->outstanding_tx;
    if (max_tx > tx_room) max_tx = tx_room;

    struct tx_item tx_items[BATCH_SIZE];
    uint64_t rx_addrs[BATCH_SIZE];
    unsigned int prepared = 0;

    for (unsigned int i = 0; i < rcvd; ++i) {
        const struct xdp_desc *desc =
            xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i);
        uint64_t rx_base = xsk_umem__extract_addr(desc->addr);
        uint64_t rx_off = xsk_umem__extract_offset(desc->addr);
        rx_addrs[i] = rx_base;

        if (prepared >= max_tx) {
            xsk->st.drop_max_tx++;
            continue;
        }

        uint64_t tx_addr;
        if (!tx_pool_alloc(xsk_tx, &tx_addr)) {
            xsk->st.drop_tx_pool_empty++;
            max_tx = prepared;
            continue;
        }

        void *rx_data = xsk_umem__get_data(xsk->umem->buffer, rx_base + rx_off);
        void *tx_data = xsk_umem__get_data(xsk_tx->umem->buffer, tx_addr);
        uint32_t processed_len = encrypt_mode ?
            packet_encrypt(rx_data, desc->len, tx_data) :
            packet_decrypt(rx_data, desc->len, tx_data);
        if (!processed_len) {
            account_sp_error(xsk);
            tx_pool_free(xsk_tx, tx_addr);
            continue;
        }
        tx_items[prepared].addr = tx_addr;
        tx_items[prepared].len = processed_len;
        ++prepared;
    }

    xsk_ring_cons__release(&xsk->rx, rcvd);
    fq_pending_push_batch(xsk, rx_addrs, rcvd);
    fq_flush_pending_nonblock(xsk, rx_fd);

    if (prepared) {
        uint32_t sent = tx_send_items_adaptive(xsk, xsk_tx, tx_fd,
                                               tx_items, prepared);
        if (sent < prepared)
            tx_pending_push_items(xsk, xsk_tx, &tx_items[sent], prepared - sent);
        complete_tx(xsk_tx);
        tx_flush_pending_nonblock(xsk, xsk_tx, tx_fd);
    }

    uint64_t now = nsec_now();
    if (now - *last_kstat_ts >= 1000000000ull) {
        struct xdp_statistics xs;
        if (xsk_read_xdp_stats(rx_fd, &xs) == 0) {
            if (xsk->st.xdp_last_valid) {
                xsk->st.k_rx_dropped +=
                    u64_delta(xs.rx_dropped, xsk->st.xdp_last.rx_dropped);
                xsk->st.k_rx_ring_full +=
                    u64_delta(xs.rx_ring_full, xsk->st.xdp_last.rx_ring_full);
                xsk->st.k_rx_fill_ring_empty_descs +=
                    u64_delta(xs.rx_fill_ring_empty_descs,
                              xsk->st.xdp_last.rx_fill_ring_empty_descs);
                xsk->st.k_rx_invalid_descs +=
                    u64_delta(xs.rx_invalid_descs, xsk->st.xdp_last.rx_invalid_descs);
                xsk->st.k_tx_invalid_descs +=
                    u64_delta(xs.tx_invalid_descs, xsk->st.xdp_last.tx_invalid_descs);
            }
            xsk->st.xdp_last = xs;
            xsk->st.xdp_last_valid = true;
        }
        *last_kstat_ts = now;
    }
    return true;
}

static void print_socket_stats(const struct xsk_socket_info *xsk,
                               const char *mode, int cpu)
{
    printf("[ifindex=%d queue=%d mode=%s] rx=%lu tx=%lu "
           "drop{max_tx=%lu pool_empty=%lu tx_full=%lu crypto_fail=%lu} "
           "sp_error{invalid_sph=%lu len_mismatch=%lu suite_invalid=%lu key_lookup_fail=%lu seq_state=%lu} "
           "kstat{rx_drop=%lu rx_ring_full=%lu rx_fill_empty=%lu} cpu=%d\n",
           xsk->ifindex, xsk->queue_id, mode,
           (unsigned long)xsk->st.rx_pkts, (unsigned long)xsk->st.tx_pkts,
           (unsigned long)xsk->st.drop_max_tx,
           (unsigned long)xsk->st.drop_tx_pool_empty,
           (unsigned long)xsk->st.drop_tx_ring_full,
           (unsigned long)xsk->st.drop_crypto_fail,
           (unsigned long)xsk->st.invalid_sph,
           (unsigned long)xsk->st.len_mismatch,
           (unsigned long)xsk->st.suite_invalid,
           (unsigned long)xsk->st.key_lookup_fail,
           (unsigned long)xsk->st.seq_state_fail,
           (unsigned long)xsk->st.k_rx_dropped,
           (unsigned long)xsk->st.k_rx_ring_full,
           (unsigned long)xsk->st.k_rx_fill_ring_empty_descs,
           cpu);
}

static void *packet_processor_queue(void *arg)
{
    const struct queue_worker_arg *worker = arg;
    int queue = worker->queue_id;
    int cpu = cpu_for_worker(queue);
    bind_current_thread_to_cpu(cpu);

    struct xsk_socket_info *inside = sockets[0][queue];
    struct xsk_socket_info *outside = sockets[1][queue];
    if (!inside || !outside) {
        EPRINT("ERROR: incomplete socket pair for queue %d\n", queue);
        keep_running = 0;
        return NULL;
    }

    struct pollfd fds[2] = {
        { .fd = xsk_socket__fd(inside->xsk), .events = POLLIN },
        { .fd = xsk_socket__fd(outside->xsk), .events = POLLIN },
    };
    uint64_t last_kstat[2] = { nsec_now(), nsec_now() };

    while (keep_running) {
        bool did_work = false;
        did_work |= process_socket_batch(inside, outside, true, &last_kstat[0]);
        did_work |= process_socket_batch(outside, inside, false, &last_kstat[1]);
        if (did_work) continue;

        for (int spin = 0; spin < IDLE_SPIN_MAX && keep_running; ++spin) {
            did_work |= process_socket_batch(inside, outside, true, &last_kstat[0]);
            did_work |= process_socket_batch(outside, inside, false, &last_kstat[1]);
            if (did_work) break;
        }
        if (!did_work) {
            (void)poll(fds, 2, 0);
            idle_wait();
        }
    }

    print_socket_stats(inside, "enc", cpu);
    print_socket_stats(outside, "dec", cpu);
    return NULL;
}

/* -------------------------- cleanup / main -------------------------- */

/* 资源回收：
 * - 删除 xsk socket / umem
 * - munmap packet buffer
 * - detach XDP
 * - close bpf obj
 */
static void socket_cleanup(struct xsk_socket_info *sockets_arr[NUM_INTERFACES][NUM_QUEUES],
                           void *packet_buffers[NUM_INTERFACES][NUM_QUEUES],
                           int ifindexes[NUM_INTERFACES],
                           const char *ifnames[NUM_INTERFACES],
                           struct bpf_object *obj)
{
    DPRINT("Cleaning up...\n");

    for (int i = 0; i < NUM_INTERFACES; i++) {
        for (int q = 0; q < NUM_QUEUES; q++) {
            if (sockets_arr[i][q]) {
                xsk_socket__delete(sockets_arr[i][q]->xsk);
                xsk_umem__delete(sockets_arr[i][q]->umem->umem);
                free(sockets_arr[i][q]->umem);
                free(sockets_arr[i][q]);
            }
            if (packet_buffers[i][q])
                munmap(packet_buffers[i][q], NUM_FRAMES * FRAME_SIZE);
        }
        if (ifindexes[i] > 0) {
            bpf_xdp_detach(ifindexes[i], XDP_FLAGS_DRV_MODE, NULL);
            DPRINT("Detached XDP program from interface %s\n", ifnames[i]);
        }
    }
    if (obj) {
        bpf_object__close(obj);
        DPRINT("Closed XDP object\n");
    }
}

int main(void)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    void *packet_buffers[NUM_INTERFACES][NUM_QUEUES] = { { NULL } };
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    pthread_t threads[NUM_QUEUES];
    struct queue_worker_arg worker_args[NUM_QUEUES];
    int ret;

    /* 计算4核机器“实际使用的CPU数量”，并打印绑核计划 */
    g_cpu_cnt = get_work_cpu_count();

    /* 读取 JSON 配置（接口名、peer IP、SP/密钥参数等） */
    if (config_init("xdp_config.json") != 0) {
        EPRINT("Failed to load configuration\n");
        return 1;
    }
    DPRINT("Configuration loaded json successfully\n");

    /* Fail before attaching XDP if the crash-safe sequence store is unusable. */
    if (sp_state_init() != 0) {
        EPRINT("Failed to initialize persistent SPH sequence state\n");
        return 1;
    }

    const char *ifnames[NUM_INTERFACES] = { IF_IN, IF_OUT };
    int ifindexes[NUM_INTERFACES] = { 0 };

    print_thread_bind_plan(g_cpu_cnt, ifnames[0], ifnames[1]);

    /* 允许锁页：BPF/UMEM 常需要 MEMLOCK（RLIM_INFINITY 简化处理） */
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        EPRINT("ERROR: setrlimit(RLIMIT_MEMLOCK) failed\n");
        return 1;
    }

    /* 获取 ifindex，并先尝试 detach 旧的 XDP 程序（避免 attach 冲突） */
    for (int i = 0; i < NUM_INTERFACES; i++) {
        ifindexes[i] = if_nametoindex(ifnames[i]);
        if (!ifindexes[i]) {
            EPRINT("ERROR: interface %s not found\n", ifnames[i]);
            socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
            return 1;
        }
        (void)bpf_xdp_detach(ifindexes[i], XDP_FLAGS_DRV_MODE, NULL);
    }
    g_config.interface.in_index = ifindexes[0];
    g_config.interface.out_index = ifindexes[1];

    /* 打开/加载内核 XDP 对象文件 */
    obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (!obj) {
        EPRINT("ERROR: opening XDP kernel program failed\n");
        socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
        return 1;
    }

    ret = bpf_object__load(obj);
    if (ret) {
        EPRINT("ERROR: loading XDP kernel program failed\n");
        socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
        return 1;
    }

    /* 查找入口 XDP 程序（名字需与你的 kern 代码一致） */
    prog = bpf_object__find_program_by_name(obj, "xdp_redirect_func");
    if (!prog) {
        EPRINT("ERROR: finding xdp_redirect_func in obj file failed\n");
        socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
        return 1;
    }

    /* 找到两张卡各自的 xsks_map（将 queue_id -> xsk fd 注入） */
    const char *xsks_map_names[NUM_INTERFACES] = { XDP_MAP_IN, XDP_MAP_OUT };
    for (int i = 0; i < NUM_INTERFACES; i++) {
        struct bpf_map *map = bpf_object__find_map_by_name(obj, xsks_map_names[i]);
        if (!map) {
            EPRINT("ERROR: finding map %s failed\n", xsks_map_names[i]);
            socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
            return 1;
        }
        xsks_map_fds[i] = bpf_map__fd(map);
    }

    /* attach XDP + 为每个队列创建 UMEM/XSK，并把 sock fd 写入 xsks_map[q] */
    for (int i = 0; i < NUM_INTERFACES; i++) {
        ret = bpf_xdp_attach(ifindexes[i], bpf_program__fd(prog),
                             XDP_FLAGS_DRV_MODE | XDP_FLAGS_REPLACE, NULL);
        if (ret) {
            EPRINT("ERROR: attaching XDP program to interface %s failed\n", ifnames[i]);
            socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
            return 1;
        }

        for (int q = 0; q < NUM_QUEUES; q++) {
            /* 为每个 (iface,queue) 分配一块 UMEM backing buffer
             * 先尝试 hugepage（MAP_HUGETLB），失败则退化为普通匿名映射。
             */
            packet_buffers[i][q] = mmap(NULL, NUM_FRAMES * FRAME_SIZE,
                                        PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                                        -1, 0);
            if (packet_buffers[i][q] == MAP_FAILED) {
                packet_buffers[i][q] = mmap(NULL, NUM_FRAMES * FRAME_SIZE,
                                            PROT_READ | PROT_WRITE,
                                            MAP_PRIVATE | MAP_ANONYMOUS,
                                            -1, 0);
                if (packet_buffers[i][q] == MAP_FAILED) {
                    EPRINT("ERROR: mmap failed for interface %s, queue %d\n", ifnames[i], q);
                    packet_buffers[i][q] = NULL;
                    socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
                    return 1;
                }
            }

            /* 创建 UMEM（预填 FQ） */
            struct xsk_umem_info *umem = xsk_configure_umem(packet_buffers[i][q],
                                                            (uint64_t)NUM_FRAMES * FRAME_SIZE);
            if (!umem) {
                EPRINT("ERROR: xsk_configure_umem failed for interface %s, queue %d\n",
                       ifnames[i], q);
                socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
                return 1;
            }

            /* 创建 XSK socket */
            sockets[i][q] = xsk_configure_socket(umem, ifnames[i], ifindexes[i], q);
            if (!sockets[i][q]) {
                EPRINT("ERROR: xsk_configure_socket failed for interface %s, queue %d\n",
                       ifnames[i], q);
                socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
                return 1;
            }

            /* 将该队列的 xsk fd 写到内核 map：内核 XDP redirect 时用 */
            int sock_fd = xsk_socket__fd(sockets[i][q]->xsk);
            ret = bpf_map_update_elem(xsks_map_fds[i], &q, &sock_fd, 0);
            if (ret) {
                EPRINT("ERROR: bpf_map_update_elem failed for interface %s, queue %d\n",
                       ifnames[i], q);
                socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
                return 1;
            }
        }
    }

    /* network_config_map：把用户态配置写入内核 map（供 XDP 程序使用） */
    struct network_config net_cfg = {
        .arp_net = { ARP_NET_A, ARP_NET_B, ARP_NET_C },
        .default_policy_action = g_config.traffic_policy.default_action,
        .policy_count = g_config.traffic_policy.count,
        .if_in_index = (__u32)ifindexes[0],
        .if_out_index = (__u32)ifindexes[1]
    };

    struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "network_config_map");
    if (!config_map) {
        EPRINT("ERROR: cannot find network_config_map\n");
        socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
        return 1;
    }

    int key = 0;
    ret = bpf_map_update_elem(bpf_map__fd(config_map), &key, &net_cfg, BPF_ANY);
    if (ret) {
        EPRINT("ERROR: cannot update network config map: %s\n", strerror(errno));
        socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
        return 1;
    }

    struct bpf_map *policy_map = bpf_object__find_map_by_name(obj, XDP_POLICY_MAP);
    if (!policy_map) {
        EPRINT("ERROR: cannot find %s\n", XDP_POLICY_MAP);
        socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
        return 1;
    }
    for (__u32 i = 0; i < g_config.traffic_policy.count; ++i) {
        ret = bpf_map_update_elem(bpf_map__fd(policy_map), &i,
                                  &g_config.traffic_policy.rules[i], BPF_ANY);
        if (ret) {
            EPRINT("ERROR: cannot load traffic policy %u: %s\n", i, strerror(errno));
            socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
            return 1;
        }
    }

    struct bpf_map *devmap = bpf_object__find_map_by_name(obj, XDP_DEVMAP);
    if (!devmap) {
        EPRINT("ERROR: cannot find %s\n", XDP_DEVMAP);
        socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
        return 1;
    }
    for (__u32 i = 0; i < NUM_INTERFACES; ++i) {
        __u32 ifindex = (__u32)ifindexes[i];
        ret = bpf_map_update_elem(bpf_map__fd(devmap), &i, &ifindex, BPF_ANY);
        if (ret) {
            EPRINT("ERROR: cannot load DEVMAP entry %u: %s\n", i, strerror(errno));
            socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
            return 1;
        }
    }

    /* 信号处理：优雅退出 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* -------------------- 创建线程（创建时也绑核一次） -------------------- */
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    for (int q = 0; q < NUM_QUEUES; q++) {
        int cpu = cpu_for_worker(q);
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu, &cpuset);
        int ar = pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset);
        if (ar)
            EPRINT("WARN: pthread_attr_setaffinity_np failed: %s\n", strerror(ar));

        worker_args[q].queue_id = q;
        ret = pthread_create(&threads[q], &attr, packet_processor_queue,
                             &worker_args[q]);
        if (ret) {
            EPRINT("ERROR: Failed to create worker for queue %d\n", q);
            pthread_attr_destroy(&attr);
            socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
            return 1;
        }
    }

#if 0 /* old two-threads-per-queue creation */
    for (int i = 0; i < NUM_INTERFACES; i++) {
        for (int q = 0; q < NUM_QUEUES; q++) {

            /* 创建线程时绑定：同队列号 -> 同CPU */
            int cpu = cpu_for_worker(q);
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(cpu, &cpuset);

            int ar = pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset);
            if (ar) {
                EPRINT("WARN: pthread_attr_setaffinity_np failed: %s\n", strerror(ar));
            }

            /* 线程入口：packet_processor，参数为该 (iface,queue) 的 RX socket */
            ret = pthread_create(&threads[i][q], &attr, packet_processor, sockets[i][q]);
            if (ret) {
                EPRINT("ERROR: Failed to create thread for interface %s, queue %d\n",
                       ifnames[i], q);
                pthread_attr_destroy(&attr);
                socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
                return 1;
            }
        }
    }
#endif

    pthread_attr_destroy(&attr);

    /* 等待所有线程退出（收到信号后 keep_running=0，线程自然退） */
#if 0
    for (int i = 0; i < NUM_INTERFACES; i++) {
        for (int q = 0; q < NUM_QUEUES; q++) {
            pthread_join(threads[i][q], NULL);
        }
    }
#endif
    for (int q = 0; q < NUM_QUEUES; q++)
        pthread_join(threads[q], NULL);

    socket_cleanup(sockets, packet_buffers, ifindexes, ifnames, obj);
    return 0;
}
