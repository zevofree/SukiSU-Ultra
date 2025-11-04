#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/slab.h>
#include "ksu_netlink.h"
#include "manual_su.h"
#include "ksu.h"

static struct sock *ksu_nl_sock = NULL;

extern int ksu_handle_manual_su_request(int option, struct manual_su_request *request);

static void ksu_netlink_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct ksu_netlink_msg *msg;
    struct ksu_netlink_msg reply;
    struct sk_buff *skb_out;
    int msg_size;
    int res;
    u32 pid;

    if (!skb) {
        pr_err("ksu_netlink: received NULL skb\n");
        return;
    }

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;

    if (!nlh || nlh->nlmsg_len < NLMSG_HDRLEN + sizeof(struct ksu_netlink_msg)) {
        pr_err("ksu_netlink: invalid message size\n");
        return;
    }

    msg = (struct ksu_netlink_msg *)nlmsg_data(nlh);

    if (msg->cmd != KSU_NETLINK_CMD_MANUAL_SU) {
        pr_warn("ksu_netlink: unknown command %d\n", msg->cmd);
        return;
    }

    pr_info("ksu_netlink: received manual_su request, option=%d, uid=%d, pid=%d\n",
            msg->option, msg->target_uid, msg->target_pid);

    memset(&reply, 0, sizeof(reply));
    reply.cmd = msg->cmd;
    reply.option = msg->option;
    reply.target_uid = msg->target_uid;
    reply.target_pid = msg->target_pid;

    struct manual_su_request request = {
        .target_uid = msg->target_uid,
        .target_pid = msg->target_pid
    };

    if (msg->option == MANUAL_SU_OP_GENERATE_TOKEN || 
        msg->option == MANUAL_SU_OP_ESCALATE) {
        memcpy(request.token_buffer, msg->token_buffer, KSU_TOKEN_LENGTH + 1);
    }

    res = ksu_handle_manual_su_request(msg->option, &request);

    reply.result = res;
    if (msg->option == MANUAL_SU_OP_GENERATE_TOKEN && res == 0) {
        memcpy(reply.token_buffer, request.token_buffer, KSU_TOKEN_LENGTH + 1);
    }

    msg_size = sizeof(struct ksu_netlink_msg);
    skb_out = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb_out) {
        pr_err("ksu_netlink: failed to allocate reply skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        pr_err("ksu_netlink: nlmsg_put failed\n");
        kfree_skb(skb_out);
        return;
    }

    NETLINK_CB(skb_out).dst_group = 0;
    memcpy(nlmsg_data(nlh), &reply, sizeof(reply));

    res = nlmsg_unicast(ksu_nl_sock, skb_out, pid);
    if (res < 0) {
        pr_err("ksu_netlink: failed to send reply: %d\n", res);
    } else {
        pr_info("ksu_netlink: reply sent successfully\n");
    }
}

int ksu_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = ksu_netlink_recv_msg,
    };

    ksu_nl_sock = netlink_kernel_create(&init_net, KSU_NETLINK_PROTOCOL, &cfg);
    if (!ksu_nl_sock) {
        pr_err("ksu_netlink: failed to create netlink socket\n");
        return -ENOMEM;
    }

    pr_info("ksu_netlink: initialized with protocol %d\n", KSU_NETLINK_PROTOCOL);
    return 0;
}

void ksu_netlink_exit(void)
{
    if (ksu_nl_sock) {
        netlink_kernel_release(ksu_nl_sock);
        ksu_nl_sock = NULL;
        pr_info("ksu_netlink: released\n");
    }
}
