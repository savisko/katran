/*
 * HwAcceleration.cpp
 *
 * Copyright Mellanox Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  Created on: Mar 5, 2019
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>

#include "HwAcceleration.h"
#include "katran/lib/BalancerStructs.h"

#include <glog/logging.h>

namespace katran {

#define MAX_CPUS 128


typedef enum bpf_perf_event_ret (*perf_event_print_fn)(void *data, uint32_t size);

static int perf_event_mmap_header(int fd, struct perf_event_mmap_page **header);

/* return LIBBPF_PERF_EVENT_DONE or LIBBPF_PERF_EVENT_ERROR */
static int perf_event_poller_multi(int *fds, struct perf_event_mmap_page **headers,
                                   unsigned int num_fds, perf_event_print_fn output_fn);

void* katran_hw_accel_daemon(void *arg);

static pthread_t daemon_thread_id;
static int numcpus = 0;
static int page_size;
static int page_cnt = 16;
static int pmu_fds[MAX_CPUS];
static struct perf_event_mmap_page *headers[MAX_CPUS];


static enum bpf_perf_event_ret print_bpf_output(void *data, uint32_t size)
{
    struct katran::hw_accel_event *e;

    e = reinterpret_cast<struct katran::hw_accel_event*>(data);

    uint32_t vip_ip = e->flow.dst;
    uint32_t real_ip = e->real_ip;
    uint32_t mark_id = e->mark_id;
    uint32_t rx_queue = e->rx_queue_index;
    uint8_t *pkt_data = (uint8_t*) (e + 1);

    char vip_string[64], real_string[64];

    printf("Pkt: vip_ip=%s, real_ip=%s, mark_id=%u, rx_queue=%u. Ethernet hdr: ",
            inet_ntop(AF_INET, &vip_ip,  vip_string,  sizeof(vip_string)),
            inet_ntop(AF_INET, &real_ip, real_string, sizeof(real_string)),
            mark_id, rx_queue);
    for (unsigned int i = 0; i < 14; i++)
        printf("%02x ", pkt_data[i]);
    printf("\n");

    return LIBBPF_PERF_EVENT_CONT;
}

static int perf_event_mmap_header(int fd, struct perf_event_mmap_page **header)
{
    void *base;
    int mmap_size;

    page_size = getpagesize();
    mmap_size = page_size * (page_cnt + 1);

    base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        return -1;
    }

    *header = reinterpret_cast<struct perf_event_mmap_page*>(base);
    return 0;
}

struct perf_event_sample {
    struct perf_event_header header;
    uint32_t size;
    char data[];
};

static enum bpf_perf_event_ret
bpf_perf_event_print(struct perf_event_header *hdr, void *private_data)
{
    if (hdr->type == PERF_RECORD_SAMPLE) {
        perf_event_print_fn fn = reinterpret_cast<perf_event_print_fn>(private_data);
        struct perf_event_sample *e = reinterpret_cast<struct perf_event_sample*>(hdr);
        enum bpf_perf_event_ret ret = fn(e->data, e->size);
        if (ret != LIBBPF_PERF_EVENT_CONT)
            return ret;
    } else if (hdr->type == PERF_RECORD_LOST) {
        struct perf_event_lost {
            struct perf_event_header header;
            uint64_t id;
            uint64_t lost;
        } *lost = reinterpret_cast<struct perf_event_lost*>(hdr);
        printf("lost %" PRIu64 " events\n", lost->lost);
    } else {
        printf("unknown event type=%d size=%u\n", hdr->type, (unsigned int)hdr->size);
    }

    return LIBBPF_PERF_EVENT_CONT;
}

static int perf_event_poller_multi(int *fds, struct perf_event_mmap_page **headers, unsigned int num_fds, perf_event_print_fn output_fn)
{
    enum bpf_perf_event_ret ret;
    struct pollfd *pfds;
    void *buf = NULL;
    size_t len = 0;
    unsigned int i;

    pfds = reinterpret_cast<struct pollfd*>(calloc(num_fds, sizeof(*pfds)));
    if (!pfds)
        return LIBBPF_PERF_EVENT_ERROR;

    for (i = 0; i < num_fds; i++) {
        pfds[i].fd = fds[i];
        pfds[i].events = POLLIN;
    }

    for (;;) {
        poll(pfds, num_fds, 1000);
        for (i = 0; i < num_fds; i++) {
            if (!pfds[i].revents)
                continue;

            printf("perf_event on fd=%d\n", pfds[i].fd);

            ret = bpf_perf_event_read_simple(headers[i],
                             page_cnt * page_size,
                             page_size, &buf, &len,
                             &bpf_perf_event_print,
                             reinterpret_cast<void*>(output_fn));
            if (ret != LIBBPF_PERF_EVENT_CONT)
                break;
        }
    }

    if (buf)
        free(buf);
    free(pfds);

    return static_cast<int>(ret);
}

void* katran_hw_accel_daemon(void *arg)
{
    int ret;

    (void)arg;

    ret = perf_event_poller_multi(pmu_fds, headers, (unsigned int)numcpus, &print_bpf_output);
    (void)ret;

    return NULL;
}

static inline int sys_perf_event_open(struct perf_event_attr *attr,
              pid_t pid, int cpu, int group_fd,
              unsigned long flags)
{
    int fd;

    fd = syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);

    return fd;
}

static bool test_bpf_perf_event(int map_fd, int num)
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .sample_type = PERF_SAMPLE_RAW,
        .wakeup_events = 1 /* get an fd notification for every event */
    };
    int i;

    for (i = 0; i < num; i++) {
        int key = i;

        pmu_fds[i] = sys_perf_event_open(&attr, -1/*pid*/, i/*cpu*/, -1/*group_fd*/, 0);

        if (pmu_fds[i] < 0) {
            int error_code = errno;
            LOG(ERROR) << "sys_perf_event_open() failed for CPU " << i << ": " << strerror(error_code);
            return false;
        }
        if (bpf_map_update_elem(map_fd, (void*) &key, (void*) &pmu_fds[i], BPF_ANY) != 0) {
            LOG(ERROR) << "bpf_map_update_elem() failed for CPU " << i;
            return false;
        }
        ioctl(pmu_fds[i], PERF_EVENT_IOC_ENABLE, 0);
    }

    return true;
}


bool startHwAccelerationThread(int bpf_map_fd)
{
    numcpus = get_nprocs();

    if (numcpus <= 0)
        return false;

    if (numcpus > MAX_CPUS)
        numcpus = MAX_CPUS;

    if (!test_bpf_perf_event(bpf_map_fd, numcpus))
        return false;

    for (int i = 0; i < numcpus; i++) {
        if (perf_event_mmap_header(pmu_fds[i], &headers[i]) < 0) {
            LOG(ERROR) << "Failed to map headers for CPU " << i;
            return false;
        }
    }

    int res = pthread_create(&daemon_thread_id, NULL, &katran_hw_accel_daemon, NULL);
    if (res != 0) {
        LOG(ERROR) << "pthread_create() failed: " << res;
        return false;
    }

    return true;
}

} // namespace katran