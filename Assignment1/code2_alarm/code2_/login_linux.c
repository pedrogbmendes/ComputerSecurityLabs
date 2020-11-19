/*****************************************************************************
	COMPUTER SECURITY - LAB 1: Identification and Authentication

	Pedro Gonçalo Mendes - pedrogo@student.chalmers.se
	Mattias Olofsson - gusolomay@student.gu.se


In this solution, when a account is blocked is set an alarm. After the alarm
devilered the signal the account is unblocked.
Pros: The system doesn't block when one account is blocked, so other users can
login into the system.
			Doesn't need a lot of resources. Only need the store (allocate memory)
the information about the account that was been blocked and then the allocate
memory is free.

Cons: We can only set one alarm at once.
(man alarm: Alarm requests are not stacked; only one SIGALRM generation can be
scheduled in this manner. If the SIGALRM signal has not yet been generated,
the call shall result in rescheduling the time at which the SIGALRM signal
is generated.
when we call alarm, and previously registered alarm clock for the process has
not yet expired, the number of seconds left for that alarm clock is returned as
the value of this function. That previously registered alarm clock is replaced
by the new value.
So the accounts can be blocked during different periods of time.

*****************************************************************************/

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"

#define TRUE 1

#define TEMP_BLOCK -1
#define BLOCK_FOREVER -2
#define LAST_ATTEMPS -5
#define IMP_UNBLOCK -6


//global variables used in the alarm
mypwent *data_blocked[10];	//stores information about blocked accounts
int counter = 0;


void allocate_mem(mypwent *passwddata, int counter, char user_check[]);

void sighandler() {
	//sighandler to ignore keyboard interruptions
	signal(SIGINT, SIG_IGN);		//ignore crtl+C
	signal(SIGTSTP, SIG_IGN);		//ignore crtl+Z
}


void  ALARMhandler(int sig){
/*when the signal is delivered to the process and this function is executed
Updates the user file with the information that some user account that was
blocked is now unblock*/
	int i;

	for(i=0; i< (10); i++){
		if(data_blocked[i] != NULL){
				data_blocked[i]->pwfailed = LAST_ATTEMPS;
				int veri = mysetpwent(data_blocked[i]->pwname, data_blocked[i]);
				if (veri == -1){
					printf("Error in Myserpwent");
					exit(0);
				}

				//free of all allocated memory
				free(data_blocked[i]->pwname);
				free(data_blocked[i]->passwd);
				free(data_blocked[i]->passwd_salt);
				free(data_blocked[i]);
				counter = counter - 1;
			}

	}
}


int main(int argc, char *argv[]) {

	mypwent *passwddata;

	char important[LENGTH] = "***IMPORTANT***";
	int veri;
	char user[LENGTH];
	char user_check[LENGTH];
	char prompt[] = "password: ";
	char *user_pass;
	char *crypt_pass;
	char salt[2];


	sighandler();
	signal(SIGALRM, ALARMhandler);

	while (TRUE) {
		/*check what important variable contains part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		//empty strings
		strcpy(user, "");
		strcpy(user_check, "");

		printf("login: ");

		/*with the function fgets, we prevent buffer overflows of the string user
		this functions only stores the last LENGTH-1 charecters read from stdin
		(keyboard) in the string*/
		if (fgets(user, LENGTH, stdin) == NULL)
			exit(0);
		sscanf(user, "%s", user_check);

		/*check to see if important variable is intact after input of login name*/
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

		//verify if the user exist and in case afirmative returns the data
		passwddata = mygetpwnam(user_check);

		if (passwddata == NULL) {
			//username doesn't exist
			printf("Login Incorrect - Username does not exist \n");
		}else{
			//passwddata != NULL -> username exists

			if (passwddata->pwfailed == TEMP_BLOCK){
				/*some user tried and failled the password too many times
				so the account is temporarily blocked*/
				printf("Your account is blocked. You have to wait\n");

			}else if (passwddata->pwfailed == IMP_UNBLOCK){
				//account is blocked forever
				printf("Your account is blocked forever. \n");

			}else{

			 	if (passwddata->pwfailed == LAST_ATTEMPS){
					printf("Your account probabily was been compromised. You have 3 more attempts until it blocks\n" );
				}

				/*wait for the user writes the password
				text is not “echoed” on the terminal*/
				user_pass = getpass(prompt);

				/*encrypt user_pass -  salt is a two-character string chosen
				from the set [a-zA-Z0-9./].  This string is used to perturb the
				algorithm in  one of 4096 different ways.*/

				/*we use strncpy only to copy 2 charecters are copied and prevent
				buffer overflows*/
				strncpy(salt, passwddata->passwd_salt, 2);
				crypt_pass = crypt(user_pass, salt);


				if (!strcmp(crypt_pass, passwddata->passwd)) {
					//if the password is correct
					printf(" Welcome to your system! :)\n");

					//print the failed attempts
					if (passwddata->pwfailed < BLOCK_FOREVER){
						//you fail the first 5 tries
						printf("Number of failed attempts= %d\n",(passwddata->pwfailed+10));
					}else{
						printf("Number of failed attempts = %d\n", passwddata->pwfailed);
					}

					passwddata->pwage = passwddata->pwage + 1;

					if((passwddata->pwage > 10)||(passwddata->pwfailed < BLOCK_FOREVER)){
						printf("ALERT - You have to change the password\n");
						printf("Entry the new password:\n");

						user_pass = getpass(prompt); //new password
						strncpy(salt, passwddata->passwd_salt, 2);
						crypt_pass = crypt(user_pass, salt);	//encryption
						passwddata->passwd = crypt_pass;
						passwddata->pwage = 1;
					}

					passwddata->pwfailed = 0;

					veri = mysetpwent(user_check, passwddata);
					if (veri == -1){
						printf("Error in Myserpwent");
						exit(0);
					}

					/*  check UID, see setuid(2) */
					if(setuid(passwddata->uid) != 0 ){
						perror("Error on UID: ");
					}

					/*  start a shell, use execve(2) */
					char *newargv[] = {NULL};
					if( execve("/bin/sh", newargv, NULL) == -1){
						perror("Error on execve: ");
					}

				}else{
					//if the password is incorrect

					//increment the number of failed attemps
					passwddata->pwfailed = passwddata->pwfailed + 1;

					if (passwddata->pwfailed <= BLOCK_FOREVER){

						if(passwddata->pwfailed == BLOCK_FOREVER){
							//account  is blocked
							printf("Your account is blocked forever. \n");
							passwddata->pwfailed = IMP_UNBLOCK;
						}else{
							//you have 3 more chances to write the correct password
							printf("Password Incorrect - Last attemps \n");

						}
						veri = mysetpwent(user_check, passwddata);
						if (veri == -1){
							printf("Error in Myserpwent");
							exit(0);
						}


					} else if( (passwddata->pwfailed) < 5 && (passwddata->pwfailed) > 0){
						//password incorrect (first 5 attemps)
						printf("Password Incorrect - try  again - you have %d more chances\n",
								(5-passwddata->pwfailed));

						veri = mysetpwent(user_check, passwddata);
						if (veri == -1){
							printf("Error in Myserpwent");
							exit(0);
						}

					}else if((passwddata->pwfailed) >= 5){
						/*you wrote the wrong password too many times
						now the account is temporarily blocked
						the user has to wait*/
						printf("You enter the wrong password to many times\n");
						passwddata->pwfailed = -1;

						/*allocating memory to store the informarion about the
						blocked account*/
						allocate_mem(passwddata, counter, user_check);

						//number of blocked accounts
						counter = counter + 1;

						veri = mysetpwent(user_check, passwddata);
						if (veri == -1){
							printf("Error in Myserpwent");
							exit(0);
						}

						/*set the alarm - the user has to wait - for the demonstration we
						only blocked the system during 20 seconds (in order to don't have
						to wait a lot of time) but in real systems, the system should be
						blocked during more time, for example, 5 or 10 minutes*/
						alarm(20);

					}
				}
			}
		}
	}
	return 0;
}


void allocate_mem(mypwent *passwddata, int count, char user_check[]) {

	data_blocked[count] = (mypwent*) malloc(sizeof(mypwent));
	int size;  		/*used to know the size of strings and avoid buffer overflows
	 and memory problems*/

	//allocating memory to the name
	size = strlen(user_check);
	data_blocked[count]->pwname = (char*) malloc( ( size*(sizeof(char)) ) + 1);
	strcpy (data_blocked[count]->pwname, user_check);

	data_blocked[count]->uid = passwddata->uid;

	//allocating memory to the password
	size = strlen(data_blocked[count]->passwd);
	data_blocked[count]->passwd = (char*) malloc( (size*(sizeof(char)) ) + 1);
	strcpy (data_blocked[count]->passwd, passwddata->passwd);

	//allocating memory to the salt
	size = strlen(data_blocked[count]->passwd_salt);
	data_blocked[count]->passwd_salt = (char*)malloc((size*(sizeof(char))) + 1);
	strcpy (data_blocked[count]->passwd_salt, passwddata->passwd_salt);

	data_blocked[count]->pwfailed = passwddata->pwfailed;

	data_blocked[count]->pwage = passwddata->pwage;
}
