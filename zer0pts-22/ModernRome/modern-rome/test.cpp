#include <string>
#include <iostream>

int main(int argc, char const *argv[])
{
    // printf("%d sizeof(short)\n", sizeof(short));
    // short i;
    // i = -1;
    // printf("-1 in memory: %p\n", i);
    // unsigned short j = i;
    // printf("-1 as an unsigned short: %hu\n", j);

    // short x;
    // std::cout << "Enter the Offset: ";
    // std::cin >> x;

    // unsigned short y = x;
    // printf("%hd in memory: %p\n", x, x);
    // printf("%hd as an unsigned short: %hu\n", x, y);

    unsigned short x;
    std::cout << "Enter X: ";
    std::cin >> x;

    printf("You entered %hu\n", x);

    short y;
    std::cout << "Enter Y: ";
    std::cin >> y;

    printf("You entered %hd\n", y);
    return 0;
}
