#ifndef ZEBRA_NETLINK_H
#define ZEBRA_NETLINK_H

struct nlsock
{
  int sock;
  int seq;
  struct sockaddr_nl snl;
  const char *name;
  int cmd;
};

extern struct zebra_t zebrad;
extern struct zebra_privs_t zserv_privs;
extern u_int32_t nl_rcvbufsize;
extern struct thread_master *master;

extern struct message nlmsg_str[];

extern int genetlink_request (int family, int type, struct nlsock *nl);
extern int netlink_socket (struct nlsock *nl, int proto, unsigned long groups);
extern int netlink_request (int family, int type, struct nlsock *nl);
extern int set_netlink_blocking (struct nlsock *nl, int *flags);
extern int set_netlink_nonblocking (struct nlsock *nl, int *flags);
extern int netlink_parse_info (int (*filter) (struct nlsock *nl, struct sockaddr_nl *,
                               struct nlmsghdr *), struct nlsock *nl,
                               void *a, unsigned int size);
extern void netlink_parse_rtattr (struct rtattr **tb, int max,
                                  struct rtattr *rta, int len);
extern int addattr32 (struct nlmsghdr *n, unsigned int maxlen, int type,
                      int data);
extern int addattr_l (struct nlmsghdr *n, unsigned int maxlen, int type,
                      void *data, int alen);
extern int rta_addattr_l (struct rtattr *rta, int maxlen, int type,
                          void *data, int alen);
extern int netlink_talk_filter (struct nlsock *nl, struct sockaddr_nl *snl, struct nlmsghdr *h);
extern int netlink_talk (struct nlmsghdr *n, struct nlsock *nl,
                         void *a, unsigned int size);
extern char *nexthop_types_desc(int x);

#endif
