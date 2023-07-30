#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[]){

	int seed = time(NULL);
	srand(seed);
	
	for ( int i = 0; i < atoi(argv[1]); ++i ) {
		printf("%d\n", rand());
	}
}