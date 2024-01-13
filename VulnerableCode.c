/* 
  Name - VulnerableCode.C 
  Date - 09/22/2005
  Programmer - R. R. Brooks

  Purpose - Illustrate multiple vulnerabilities involving buffer
  overflow attacks. Contains a series of subroutines exhibiting
  poor coding practices.
 
  Input - A vector of numeric values, followed by a string filename.

  Output - Nothing useful. The program merely serves as a template
  for allowing students to exploit the various coding mistakes made.

 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int GlobalBuf[42];

void SmashHeap(int argnum, char **argv)
{
  int *DynamicMem;
  int TempChar;
  int i=0;
  int f1;

  printf("In SmashHeap(argc)\n");
  DynamicMem=malloc(24 * sizeof(int));
  if((f1=open(argv[argnum-1],0))==-1)
    printf("Error-can not open file %s \n",argv[argnum-1]);
  while(read(f1,&TempChar,4)>0){
     DynamicMem[i++]=TempChar;
     printf("i=%i ,sizeof(char)=%i,sizeof(int)=%i \n",i,
	    sizeof(char),sizeof(int));
  }
}

void EnterDataToVulnerableBuffer(int *Buffer,int argc,char **argv)
{
  int TempChar;
  int i=0;
  int f1;

  printf("In EnterDataToVulnerableBuffer()\n");
  if((f1=open(argv[argc-1],0))==-1)
    printf("Error-can not open file %s \n",argv[argc-1]);
  while(read(f1,&TempChar,4)>0){
     Buffer[i++]=TempChar;

     printf("i=%i ,sizeof(char)=%i,sizeof(int)=%i \n",i,
	    sizeof(char),sizeof(int));
  }

}

void VulnerableLocalData(int argc, char **argv)
{
  int BufOve[14];

  printf("In VulnerableLocalData()\n");

  EnterDataToVulnerableBuffer(BufOve,argc,argv);
}

void RecursivePrefixLocal(int i,int argc,char **argv)
{
  printf("In RecursivePrefixLocal(%i)\n",i);

  if(--i) RecursivePrefixLocal(i,argc,argv);
  else VulnerableLocalData(argc,argv);
}

void AttackGlobal(int argc, char **argv)
{
  int TempChar;
  int i=0;
  int f1;

  printf("In AttackGlobal()\n");
  printf("argc=%i, argv[%i]=%s \n",argc,argc,argv[argc-1]);
  if((f1=open(argv[argc-1],0))==-1)
    printf("Error-can not open file %s \n",argv[argc-1]);
  while(read(f1,&TempChar,4)>0){
     GlobalBuf[i++]=TempChar;
     printf("i=%i ,sizeof(char)=%i,sizeof(int)=%i \n",i,
	    sizeof(char),sizeof(int));
  }
 }

void RecursivePrefixGlobal(int i,int argc, char **argv)
{
  printf("In RecursivePrefixGlobal(%i)\n",i);
  printf("argc=%i, argv[%i]=%s \n",argc,argc,argv[argc-1]);
  if(--i) RecursivePrefixGlobal(i,argc,argv);
  else AttackGlobal(argc,argv);
}

void ArcInjection(char *R)
{
  printf("In ArcInjection()\n");
  system(R);
}

void PrintfVulnerability(char *F)
{
  printf(F);
}

void (*FuncPtr)(int,int, char **);

int main(int argc, char **argv)
{
  char Command[]="ls >yada.dat                   ";
  int i=1;
  
  FuncPtr=RecursivePrefixLocal;
  while(i < argc-1){
    printf("main loop i=%d, argv[i]=%s, %d, argv[argc-1]=%s\n",i,
	   argv[i],argv[i][0],argv[argc-1]);
    switch(argv[i][0]-48){
    case 1:
      SmashHeap(argc,argv);
      break;
    case 2:
      VulnerableLocalData(argc,argv);
      break;
    case 3:
      RecursivePrefixLocal(argv[++i][0]-48,argc,argv);
      break;
    case 4:
      AttackGlobal(argc,argv);
      break;
    case 5:
      ArcInjection(Command);
      break;
    case 6:
      FuncPtr(argv[++i][0]-48,argc,argv);
      break;
    case 7:
      RecursivePrefixGlobal(argv[++i][0]-48,argc,argv);
      break;
    case 8:
      PrintfVulnerability(argv[++i]);
      break;
    default:
      printf("%s is not recognized by this program",argv[i++]);
      printf(" enter in a sequence of 1 digit numbers \n separated");
      printf(" by spaces.\n");
      printf("Numbers 1-7 refer to functions with buffer overflow");
      printf(" vulnerabilities.\n");
      printf("Number 8 does a format string attack\n.");
    }
    i++;
  }

  return(1);
}
      
