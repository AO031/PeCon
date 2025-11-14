#include <stdio.h>
#include <Windows.h>

int main() {
	int a = 1;
	__try {
		a = 2;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		a = 3;
	}
	return 0;
}