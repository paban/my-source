#ifndef __RSVP_INCLUDES__
#define __RSVP_INCLUDES__

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <ctype.h>
#include<math.h>
#include<errno.h>
#include <zebra.h>
#include "thread.h"
#include "vty.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "patricia.h"

#include "general.h"
#include "messages.h"
#include "rsvp_packet.h"
#include "te_lib.h"
#include "rsvp_psb.h"
#include "rsvp_rsb.h"
#include "rsvp_socket.h"
#include "rsvp_utilities.h"
#include "rsvp_decode.h"
#include "rsvp_encode.h"
#include "rsvp_api.h"

#define RSVP_VTY_PORT		2699
#define RSVP_DEFAULT_CONFIG	"rsvpd.conf"

#endif
