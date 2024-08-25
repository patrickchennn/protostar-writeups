#include <stdio.h>

int main()
{
	char *foo = "Hello, %p!";
	printf(foo);  // Bug: There's no argument for %p
	
	return 0;
}
