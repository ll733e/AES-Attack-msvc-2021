#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <Windows.h>

#define DIR "C:\\Users\\louxsoen\\Documents\\부채널연구\\AES CPA\\"
#define traceFN "a.traces"
#define ctFN "ciphertext.txt"
#define ptFN "plaintext.txt"
#define startpt	50001
#define endpt 71000

typedef unsigned char u8;

static u8 RSBOX[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

void gotoxy(int x, int y)
{
	COORD Pos = { x - 1, y - 1 };

	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), Pos);
}

int main()
{
	u8** CT = NULL;
	u8		temp[34];
	u8		iv, hw_iv; // 데이터의 해밍웨이터
	u8		R10[16];	 // 10라운드 마스터키
	double	maxCorr; // 상관계수 최대값(PEAK마다 바)
	double* corr;	// 코렐레이션 값
	double	HW;	  // 해밍웨이트의 합, 전력량의 합
	double	HW_2, * WT_2; // 해밍웨이트 제곱들의 합, 전력량의 제곱들의 합
	double* hw_wt;		// 해밍 x 전력의 합
	double* WT; // 실제 전력값들의 합, 전력값들 제곱의 합
	double	a, b, c;
	float** WT_data;  // 파동을 전체 저장할 데이터
	int		TraceNum, TraceLength;
	int		key, maxkey;
	int		x, y;	      // plaintext 파일 가져올 때 쓰이는 변수
	int		i, j, k;	  // 반복문에 쓰이는 변수
	char	buf[256];	  // 파일 디렉토리를 덮어 쓸 임시값
	double	cur, all;
	FILE* rfp, * wfp;
	printf("\n    IA&AI Sec LAB");
	// DATA
	sprintf(buf, "%s%s", DIR, traceFN);
	rfp = fopen(buf, "rb");
	if (rfp == NULL)
		printf("%s 파일 읽기 오류", traceFN);

	fread(&TraceLength, sizeof(int), 1, rfp); // TraceLength를 int 크키 만큼 한번 읽는다 (4bytes)
	fread(&TraceNum, sizeof(int), 1, rfp);	  // TraceNum을 int 크기 만큼 한번 읽는다 (4bytes)

	// DATA 동적 할당
	WT_data = (float**)calloc(TraceNum, sizeof(float*));
	for (i = 0; i < TraceNum; i++)
		WT_data[i] = (float*)calloc(TraceLength, sizeof(float));

	// DATA 
	for (i = 0; i < TraceNum; i++) {
		fread(WT_data[i], sizeof(float), TraceLength, rfp);
	}
	fclose(rfp);

	// PLAINTEXT
	sprintf(buf, "%s%s", DIR, ctFN);
	rfp = fopen(buf, "r"); // read binary가 아님. 무조건 r
	if (rfp == NULL)
		printf("%s 파일 읽기 오류", ctFN);

	CT = (u8**)calloc(TraceNum, sizeof(u8*)); // 역참조 : 값 넣어주면 안정화
	for (i = 0; i < TraceNum; i++)
		CT[i] = (u8*)calloc(16, sizeof(u8));

	// ptFN 가공
	for (i = 0; i < TraceNum; i++) {
		fread(temp, sizeof(char), 33, rfp);
		for (j = 0; j < 16; j++) {
			x = temp[2 * j];
			y = temp[2 * j + 1];

			if (x >= 'a' && x <= 'z') x = x - 'a' + 10;
			else if (x >= 'A' && x <= 'Z') x = x - 'A' + 10;
			else if (x >= '0' && x <= '9') x -= '0';

			if (y >= 'a' && y <= 'z') y = y - 'a' + 10;
			else if (y >= 'A' && y <= 'Z') y = y - 'A' + 10;
			else if (y >= '0' && y <= '9') y -= '0';

			CT[i][j] = x * 16 + y;
		}
	}



	corr = (double*)calloc(TraceLength, sizeof(double));
	WT = (double*)calloc(TraceLength, sizeof(double));
	WT_2 = (double*)calloc(TraceLength, sizeof(double));
	hw_wt = (double*)calloc(TraceLength, sizeof(double));

	for (i = 0; i < TraceNum; i++)
	{
		for (j = startpt; j < endpt; j++) {
			WT[j] += WT_data[i][j];
			WT_2[j] += WT_data[i][j] * WT_data[i][j];
		}
	}

	for (int i = 0; i < 16; i++)
	{
		maxCorr = 0;
		maxkey = 0;
		for (key = 0; key < 256; key++) {
			HW = 0;
			HW_2 = 0;
			memset(hw_wt, 0, sizeof(double) * TraceLength);
			for (j = 0; j < TraceNum; j++) { // hw 구하는 곳

				iv = RSBOX[CT[j][i] ^ key];
				hw_iv = 0;
				for (k = 0; k < 8; k++) hw_iv += ((iv >> k) & 1);

				HW += hw_iv;
				HW_2 += hw_iv * hw_iv; // 오버플로우 방지 스카우트

				for (k = startpt; k < endpt; k++) {
					hw_wt[k] += hw_iv * WT_data[j][k];
				}
			}

			for (j = startpt; j < endpt; j++) { // 상관계수 구하는 곳

				a = (double)TraceNum * hw_wt[j] - WT[j] * HW;
				b = sqrt((double)TraceNum * WT_2[j] - WT[j] * WT[j]);
				c = sqrt((double)TraceNum * HW_2 - HW * HW);

				//printf("%lf %lf %lf\n", a, b, c);

				corr[j] = a / (b * c);
				if (fabs(corr[j]) > maxCorr) {
					maxkey = key;
					maxCorr = fabs(corr[j]);
				}

			}
			gotoxy(25, 25);
			printf("\rProgress %.1lf%%  |  %02dth Block : %.1lf%%", (((double)key / 255) * 100 / 16) + (100 / 16 * i), i, ((double)key / 255) * 100);

			sprintf(buf, "%sct\\%02d_%02X.ct", DIR, i, key);
			fflush(stdout);
			wfp = fopen(buf, "wb");
			if (wfp == NULL)
				printf("블록 쓰기 에러\n");
			fwrite(corr, sizeof(double), TraceLength, wfp);
			fclose(wfp);

		}

		if (i == 0)
		{
			gotoxy(1, 1);
			printf("\n\n=====================================\n\n   KEY : ");
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
			printf("0x%02X", maxkey);
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
			printf("       CORR :");
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
			printf("%lf", maxCorr);
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
		}
		else if (i <= 16) {
			gotoxy(10, i + 5);
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
			printf("0x%02X", maxkey);
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
			printf("       CORR :");
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
			printf("%lf", maxCorr);
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
		}
		R10[i] = maxkey;
	}
	printf("\n\n");

	printf("MASTER KEY : 0x");
	for (int i = 0; i < 16; i++)	printf("%02X", R10[i]);
	puts("");

	free(CT);
	free(hw_wt);
	free(WT);
	free(WT_2);
	free(WT_data);
	free(corr);
}