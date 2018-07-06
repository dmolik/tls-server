#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
	char a[14] = "Hello ";
	char b[8]  = " World!";
	strncat(a,b,6);
	printf("%s\n", a);
}
