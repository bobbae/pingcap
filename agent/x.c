#include <stdio.h>
int main()
{
	FILE *cmd = popen("ls", "r");
	char result[1024];
	while (fgets(result, sizeof(result), cmd) != NULL)
		printf("%s\n", result);
	pclose(cmd);
	return 0;
}
