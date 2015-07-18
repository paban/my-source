
#ifndef __GENERAL_H__
#define __GENERAL_H__

typedef unsigned long HANDLE;

typedef unsigned char BOOL;

typedef unsigned char uns8;
typedef unsigned short uns16;
typedef unsigned int uns32;

#define FALSE 0
#define TRUE  1

typedef unsigned int IPV4_ADDR;
typedef struct
{
  IPV4_ADDR IpAddr;
  uns8 PrefixLength;
  uns8 Loose;
} ER_HOP;

typedef enum
{
  E_OK,
  E_ERR
} E_RC;


#define LOCAL_ADDRESS       "127.0.0.1"
#define RSVP_CONSOLE_PORT   2002
#define RSVP_TE_PORT        2003
#define TE_SIM_PORT         2004
#define TE_APP_PORT         2004
#define TE_APP_PORT2        2012
#define TE_APP_PORT3        2013
#define TE_APP_CONSOLE_PORT 2011
#define HAS_TE_SIM 1

#endif
