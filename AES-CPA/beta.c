#include <stdio.h>
#define _CRT_SECURE_NO_WARNINGS

#define DIR "C:\\Users\\louxsoen\\Documents\\AES CPA\\"
#define traceFN "a.traces"
#define ptFN "plaintext.txt"
#define ctFN "ciphertext.txt"

int main()
{
	unsigned char** pt;
	float** trace;
	int		TraceNum, TraceLength;
	char buf[256];
	FILE*	rfp, * wfp;
	
	sprintf(buf, "%s%s", DIR, traceFN);
	rfp = fopen(buf, "rb");
	if (rfp == NULL)
		printf("%s ���� �ϱ� ����", traceFN);

	fread(&TraceLength, sizeof(int), 1, rfp); // TraceLength�� int ũŰ ��ŭ �ѹ� �д´� (4bytes)
	fread(&TraceNum, sizeof(int), 1, rfp);	  // TraceNum�� int ũ�� ��ŭ �ѹ� �д´� (4bytes)	

}