#include <zebra.h>

#include "version.h"
#include "getopt.h"
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "memory.h"
#include "prefix.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"

#include "ldp.h"
#include "ldp_vty.h"
#include "ldp_zebra.h"
#include "ldp_interface.h"

/* ldpd privileges */
zebra_capabilities_t _caps_p [] =
{
  ZCAP_NET_RAW,
  ZCAP_BIND,
  ZCAP_NET_ADMIN,
  ZCAP_SETID,
};

struct zebra_privs_t ldpd_privs =
{
#if defined(QUAGGA_USER) && defined(QUAGGA_GROUP)
  .user = QUAGGA_USER,
  .group = QUAGGA_GROUP,
#endif
#ifdef VTY_GROUP
  .vty_group = VTY_GROUP,
#endif
  .caps_p = _caps_p,
  .cap_num_p = sizeof(_caps_p)/sizeof(_caps_p[0]),
  .cap_num_i = 0
};

/* Configuration filename and directory. */
char config_default[] = SYSCONFDIR LDP_DEFAULT_CONFIG;

/* LDPd options. */
struct option longopts[] =
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "pid_file",    required_argument, NULL, 'i'},
  { "log_mode",    no_argument,       NULL, 'l'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_addr",    required_argument, NULL, 'A'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "user",        required_argument, NULL, 'u'},
  { "group",       required_argument, NULL, 'g'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
char *pid_file = PATH_LDPD_PID;

/* Help information display. */
static void __attribute__ ((noreturn))
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\n\
Daemon which manages LDP related configuration.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-u, --user         User and group to run as\n\
-g, --group        Group to run as\n\
-h, --help         Display this help and exit\n\
-v, --version      Print program version\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }
  exit (status);
}

/* SIGHUP handler. */
void 
sighup (int sig)
{
  zlog (NULL, LOG_INFO, "SIGHUP received");
}

/* SIGINT handler. */
void
sigint (int sig)
{
  zlog (NULL, LOG_INFO, "Terminating on signal");
  exit (0);
}

/* SIGUSR1 handler. */
void
sigusr1 (int sig)
{
  zlog_rotate (NULL);
}

struct quagga_signal_t ldp_signals[] =
{
  {
    .signal = SIGHUP,
    .handler = &sighup,
  },
  {
    .signal = SIGUSR1,
    .handler = &sigusr1,
  },
  {
    .signal = SIGINT,
    .handler = &sigint,
  },
  {
    .signal = SIGTERM,
    .handler = &sigint,
  },
};


/* LDP main routine. */
int
main (int argc, char **argv)
{
  char *p;
  char *vty_addr = NULL;
  int vty_port = LDP_VTY_PORT;
  int daemon_mode = 0;
  char *config_file = NULL;
  char *progname;
  struct thread thread;

  /* Set umask before anything for security */
  umask (0027);

  /* preserve my name */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  /* Invoked by a priviledged user? -- endo. */
  if (geteuid () != 0)
    {
      errno = EPERM;
      perror (progname);
      exit (1);
    }

  zlog_default = openzlog (progname, ZLOG_LDP,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

  while (1) 
    {
      int opt;
  
      opt = getopt_long (argc, argv, "dlf:i:hA:P:u:g:v", longopts, 0);

      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'A':
	  vty_addr = optarg;
          break;
	case 'i':
	  pid_file = optarg;
          break;
	case 'P':
          /* Deal with atoi() returning 0 on failure, and ldpd not
             listening on ldp port... */
          if (strcmp(optarg, "0") == 0)
            {
              vty_port = 0;
              break;
            }
          vty_port = atoi (optarg);
          vty_port = (vty_port ? vty_port : LDP_VTY_PORT);
          break;
        case 'u':
          ldpd_privs.user = optarg;
          break;
        case 'g':
          ldpd_privs.group = optarg;
          break;
	case 'v':
	  print_version (progname);
	  exit (0);
	  break;
	case 'h':
	  usage (progname, 0);
	  break;
	default:
	  usage (progname, 1);
	  break;
	}
    }

  /* Make master thread emulator. */
  master = thread_master_create ();

  /* Vty related initialize. */
  zprivs_init (&ldpd_privs);
  signal_init (master, Q_SIGC(ldp_signals), ldp_signals);
  cmd_init (1);
  vty_init (master);
  memory_init ();

  /* LDP inits */
  ldp_init ();
  ldp_interface_init ();
  ldp_vty_init ();
  ldp_vty_show_init ();
  ldp_zebra_init ();

  /* Sort all installed commands. */
  sort_node();

  /* Configuration file read*/
  vty_read_config(config_file, config_default);

  /* Change to the daemon program. */
  if (daemon_mode)
    daemon(0, 0);

  /* Process id file create. */
  pid_output(pid_file);

  /* Create VTY socket */
  vty_serv_sock (vty_addr, vty_port, LDP_VTYSH_PATH);

  /* Print banner. */
  zlog_notice ("LDPd %s starting vty@%d", QUAGGA_VERSION, vty_port);

   /* Fetch next active thread. */
  while(thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached... */
  exit (0);
}
