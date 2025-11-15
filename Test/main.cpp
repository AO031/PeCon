#include <stdio.h>
#include <Windows.h>

int main() {
	__try {
		int a = 2;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		int a = 3;
	}
	return 0;
}