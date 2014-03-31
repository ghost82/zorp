#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PORT ((uint16_t) 12345)

int
make_socket (uint16_t port)
{
  int sock, flag = 1;
  struct sockaddr_in name;

  /* Create the socket. */
  sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      perror("socket");
      exit(EXIT_FAILURE);
    }

  /* Set the reuse flag. */
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
    {
      perror("setsockopt(SOL_SOCKET, SO_REUSEADDR)");
      exit(EXIT_FAILURE);
    }

  /* Give the socket a name. */
  name.sin_family = AF_INET;
  name.sin_port = htons(port);
  name.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(sock, (struct sockaddr *) &name, sizeof (name)) < 0)
    {
      perror("bind");
      exit(EXIT_FAILURE);
    }

  return sock;
}

void
print_tos(int sock)
{
  unsigned char buf[256];
  socklen_t size;

  size = sizeof(buf);
  if (getsockopt(sock, SOL_IP, IP_PKTOPTIONS, &buf, &size) < 0)
    {
      perror("getsockopt(SOL_IP, IP_PKTOPTIONS)");
      exit(EXIT_FAILURE);
    }
  else
    {
      struct msghdr msg;
      struct cmsghdr *cmsg;
      int tos_found = 0;

      msg.msg_controllen = size;
      msg.msg_control = buf;

      for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
	{
	  if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TOS)
	    {
	      unsigned char tos = *((unsigned char *) CMSG_DATA(cmsg));

	      tos_found = 1;
	      fprintf(stderr, "TOS: 0x%x\n", tos);
	    }
	}

      if (!tos_found)
	{
	  fprintf(stderr, "Unable to query TOS\n");
	  exit(EXIT_FAILURE);
	}
    }
}

int
main(void)
{
  int sock, new_;
  int flag;
  struct sockaddr_in clientname;
  unsigned char buf[256];
  socklen_t size;

  sock = make_socket(PORT);
  if (listen(sock, 1) < 0)
    {
      perror("listen");
      exit(EXIT_FAILURE);
    }

  flag = 1;
  if (setsockopt(sock, SOL_IP, IP_RECVTOS, &flag, sizeof(flag)) < 0)
    {
      perror("setsockopt(SOL_IP, IP_RECVTOS)");
      exit(EXIT_FAILURE);
    }

  fprintf(stderr, "Listening on port %hu\n", PORT);

  size = sizeof(clientname);
  new_ = accept(sock, (struct sockaddr *) &clientname, &size);
  if (new_ < 0)
    {
      perror("accept");
      exit(EXIT_FAILURE);
    }

  fprintf(stderr, "Connect from %s:%hu\n",
	  inet_ntoa(clientname.sin_addr),
	  ntohs(clientname.sin_port));

  print_tos(new_);

  if (read(new_, buf, 1) < 0)
    {
      perror("read");
      exit(EXIT_FAILURE);
    }

  print_tos(new_);

  close(new_);
  close(sock);

  exit(EXIT_SUCCESS);
}
