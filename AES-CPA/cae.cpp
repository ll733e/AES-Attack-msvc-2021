#include <iostream>
using namespace std;

int main()
{
	int num;
	
	cout << ">> ";
	cin >> num;
	int* arr = new int[num];
	cout << ">> ";
	for (int i = 0; i < num; i++)
	{
		cin >> arr[i];
	}

	for (int i = 1; i < num; i++)
		arr[0] += arr[i];

	cout << "Á¤´äÀº " << arr[0];

	delete[] arr;
}