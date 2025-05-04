#include <stdio.h>

int square(int x) {
    int result = x * x;
    return result;
}

int add_offset(int x) {
    int offset = 10;
    return x + offset;
}

void conditional_branch_test(int x) {
    printf("Testing input: %d\n", x);

    if (x == 42) {
        printf("The answer to everything!\n");
    } else if (x > 50) {
        printf("Greater than 50\n");
    } else {
        printf("Something else\n");
    }
}

int main() {
    int input = 42;
    int result = square(input);
    printf("Square: %d\n", result);

    result = add_offset(result);
    printf("Offset result: %d\n", result);

    conditional_branch_test(input);

    return 0;
}
