#include<stdio.h>
#include<stdint.h>
#include<netinet/in.h>
int i;
uint32_t fopen_n_convert(char *file){
	uint32_t hbo, nbo;
	FILE *fp=fopen(file, "r");

	i++;
	fread(&nbo, sizeof(uint32_t), 1, fp);
	hbo=ntohl(nbo);
	printf("file %d=%d(0x%x)\n", i, hbo, hbo);

	return hbo;
}
