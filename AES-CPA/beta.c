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
		printf("%s 파일 일기 오류", traceFN);

	fread(&TraceLength, sizeof(int), 1, rfp); // TraceLength를 int 크키 만큼 한번 읽는다 (4bytes)
	fread(&TraceNum, sizeof(int), 1, rfp);	  // TraceNum을 int 크기 만큼 한번 읽는다 (4bytes)	

}