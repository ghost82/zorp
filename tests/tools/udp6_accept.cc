#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PORT 12345

int
make_socket (uint16_t port)
{
  int sock, flag = 1;
  struct sockaddr_in6 name;

  /* Create the socket. */
  sock = socket(PF_INET6, SOCK_DGRAM, 0);
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
  name.sin6_family = AF_INET6;
  name.sin6_port = htons(port);
  memcpy(&name.sin6_addr, &in6addr_any, sizeof(in6addr_any));
  if (bind(sock, (struct sockaddr *) &name, sizeof (name)) < 0)
    {
      perror("bind");
      exit(EXIT_FAILURE);
    }

  return sock;
}

int
main(void)
{
  int sock, new_;
  struct sockaddr_in6 clientname;
  char buf[256];
  socklen_t size;

  sock = make_socket(PORT);

  fprintf(stderr, "Receiving on port %d\n", PORT);

  if (recv(sock, buf, sizeof(buf), MSG_PEEK) < 0)
    {
      perror("recv");
      exit(EXIT_FAILURE);
    }

  size = sizeof(clientname);
  new_ = accept(sock, (struct sockaddr *) &clientname, &size);
  if (new_ < 0)
    {
      perror("accept");
      exit(EXIT_FAILURE);
    }

  fprintf(stderr, "Connect from %s:%hu\n",
          inet_ntop(AF_INET6, &clientname.sin6_addr, buf, sizeof(buf)),
          ntohs(clientname.sin6_port));

  if (read(new_, buf, 1) < 0)
    {
      perror("read");
      exit(EXIT_FAILURE);
    }

  fprintf(stderr, "Byte received: 0x%x\n", buf[0]);

  close(new_);
  close(sock);

  exit(EXIT_SUCCESS);
}
