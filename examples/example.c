#include <stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shout/shout.h>

int main()
{
	shout_conn_t conn;
	char buff[4096];
	long read, ret, total;

	shout_init_connection(&conn);

	conn.ip = "127.0.0.1";
	conn.port = 8765;
	conn.password = "hackme";
	conn.mount = "/example";

	if (shout_connect(&conn)) {
		printf("Connected to server...\n");
		total = 0;
		while (1) {
			read = fread(buff, 1, 4096, stdin);
			total = total + read;

			if (read > 0) {
				ret = shout_send_data(&conn, buff, read);
				if (!ret) {
					printf("DEBUG: Send error: %i...\n", conn.error);
					break;
				}
			} else {
				break;
			}

			shout_sleep(&conn);
		}
	} else {
		printf("Couldn't connect...%i\n", conn.error);
	}

	shout_disconnect(&conn);

	return 0;
}
