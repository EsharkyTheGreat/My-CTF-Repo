#include <iostream>
#include <vector>
#include <assert.h>
using namespace std;
#define ll long long

int main()
{
    vector<ll> vec;
    ll n;
    cout << "Enter value of n: ";
    cin >> n;
    ll x;
    cout << endl
         << "Enter thr elements" << endl;
    for (ll i = 0; i < n; i++)
    {
        cin >> x;
        vec.push_back(x);
    }
    printf("Accessing 0th Index: %p\n", vec[0]);
    printf("Accessing Nth Index: %p\n", vec[n]);
    printf("Accessing Negative Index %p\n", vec[-1]);
}