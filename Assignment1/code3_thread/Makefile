all: login_linux

mylogin: mylogin.c pwent.h pwent.c
	gcc -g -Wall pwent.c mylogin.c -lpthread -lcrypt -o mylogin

login_linux: login_linux.c pwent.h pwent.c
	gcc -g -Wall pwent.c login_linux.c -lpthread -lcrypt -o login_linux

clean:
	rm -f *.o mylogin login_linux
