#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <fcntl.h>  
#include <unistd.h>
#include <sys/socket.h>
//#include <sys/types.h>  
//#include <sys/stat.h>  
  
#define FIFO_NAME "/tmp/my_fifo"
  
void watchdog()  
{  
    int n, counter, overflow_flag, fd;
	FILE *fp;
    char buf[1024];
  
 	if(unlink(FIFO_NAME) == 0){
		printf("[I] %s found, deleted.\n", FIFO_NAME);
	}
	if(mkfifo(FIFO_NAME, 0777) < 0){   
		perror("mkfifo()");
		exit(-1);
	}
  
    printf("[I] Process id: %d opening %s O_RDONLY\n", getpid(), FIFO_NAME);  
    if((fd = open(FIFO_NAME, O_RDONLY)) < 0){
		perror("open()");
		exit(-1);
	}

	n = 0;
	counter = 0;
	overflow_flag = 0;
	
	do{  
		n = read(fd, buf + counter, 1);
		if(n == 0){
			usleep(5000);
			continue;
		}
		if(buf[counter] == '\n'){
			if(overflow_flag == 0){
				buf[counter] = '\0';
				printf("> %s\n", buf);
				if(strncmp("exit", buf, counter+1) == 0){
					break;
				}
				system(buf);
			}
			else{
				overflow_flag = 0;
			}
			counter = 0;
			continue;
		}
		counter++;
		if(counter >= 1024 && overflow_flag == 0){
			printf("[E] Command which has more than 1023 chars is not acceptable.\n");
			overflow_flag = 1;
			counter = 0;
		}
	}while(n >= 0);

	if(n < 0){
		perror("read()");
	}
	else{
		printf("Exit command received, cleaning up and exiting.\n");
	}

	close(fd);  
 	unlink(FIFO_NAME);
    exit(0);
}

void exploit(char *cmd){
    int fd[2];
    char buf[1024];
    socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
    if (fork() == 0) {
        close(fd[0]);
        dup2(fd[1], STDOUT_FILENO);
        dup2(fd[1], STDIN_FILENO);
        dup2(fd[1], STDERR_FILENO);
        close(fd[1]);
        execl("/bin/bash", "/bin/bash", NULL);
    } else {
        close(fd[1]);
        /* 
          read(fd[0], buf, 1);{
			  printf(buf);
		  }
		*/
		char *a= "echo -e \"test\\nhhe\"\nexit\n";
		printf(a);
        write(fd[0], a, 9);
        shutdown(fd[0], SHUT_WR);   // 通知对端数据发送完毕
          read(fd[0], buf, 1024);{
			  printf(buf);
		  }
        close(fd[0]);
        printf("waiting");
        wait(NULL);
    }
}

int main(int argc, char **argv){
	if(argc != 2){
		watchdog();
	}
	exploit(argv[1]);
	return 0;
}
