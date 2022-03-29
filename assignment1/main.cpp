#include "func.h"
int main(int argc, char *argv[]){
	uint32_t a=fopen_n_convert(argv[1]), b=fopen_n_convert(argv[2]);
	uint32_t sum=a+b;

	printf("answer=%d(0x%x)", sum, sum);
	
	return 0;
}
