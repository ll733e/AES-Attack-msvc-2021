#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#define _CRT_SECURE_NO_WARNINGS

#define DIR "C:\\Users\\louxsoen\\Documents\\부채널연구\\AES CPA\\"
#define traceFN "a.traces"
#define ptFN "plaintext.txt"
#define ctFN "ciphertext.txt"

#define startpt	21000
#define endpt 31000

typedef unsigned char u8;

static u8 SBOX[256] =
{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

int main()
{
	u8**	plaintext = NULL;
	u8		temp[34];
	u8		iv, hw_iv; // 데이터의 해밍웨이터
	double	maxcorr; // 상관계수 최대값(PEAK마다 바)
	double* corr;	// 코렐레이션 값
	double	Sy;	  // 해밍웨이트의 합, 전력량의 합
	double	Syy, *Sxx; // 해밍웨이트 제곱들의 합, 전력량의 제곱들의 합
	double	*Sxy;		// 해밍 x 전력의 합
	double  *Sx; // 실제 전력값들의 합, 전력값들 제곱의 합
	double	a, b, c;
	float** data;  // 파동을 전체 저장할 데이터
	int		TraceNum, TraceLength;
	int		key, maxkey;
	int		x, y;	      // plaintext 파일 가져올 때 쓰이는 변수
	int		i, j, k;	  // 반복문에 쓰이는 변수
	char	buf[256];	  // 파일 디렉토리를 덮어 쓸 임시값
	FILE*	rfp, * wfp;
	

	// DATA
	sprintf(buf, "%s%s", DIR, traceFN);
	rfp = fopen(buf, "rb");
	if (rfp == NULL)
		printf("%s 파일 읽기 오류", traceFN);

	fread(&TraceLength, sizeof(int), 1, rfp); // TraceLength를 int 크키 만큼 한번 읽는다 (4bytes)
	fread(&TraceNum, sizeof(int), 1, rfp);	  // TraceNum을 int 크기 만큼 한번 읽는다 (4bytes)	
	
	// DATA 동적 할당
	data = (float**)calloc(TraceNum, sizeof(float*));
	for (i = 0 ; i < TraceNum; i++)
		data[i] = (float*)calloc(TraceLength, sizeof(float));
	
	// DATA 
	for (i = 0; i < TraceNum; i++)
	{
		fread(data[i], sizeof(float), TraceLength, rfp);
	}
	fclose(rfp);

	// PLAINTEXT
	sprintf(buf, "%s%s", DIR, ptFN);
	rfp = fopen(buf, "r"); // read binary가 아님. 무조건 r
	if (rfp == NULL)
		printf("%s 파일 읽기 오류", ptFN);

	plaintext = (u8**)calloc(TraceNum, sizeof(u8*)); // 역참조 : 값 넣어주면 안정화
	for (i = 0; i < TraceNum; i++)
		plaintext[i] = (u8*)calloc(16, sizeof(u8));
	
	// ptFN 가공
	for (i = 0; i < TraceNum; i++)
	{
		fread(temp, sizeof(char), 34, rfp);
		for(j = 0 ; j < 16 ; j++)
		{
			x = temp[2 * j];
			y = temp[2 * j + 1];
				
			if (x >= 'a' && x <= 'z') x = x - 'a' + 10;
			else if (x >= 'A' && x <= 'Z') x = x - 'A' + 10;
			else if (x >= '0' && x <= '9') x -= '0';

			if (y >= 'a' && y <= 'z') y = y - 'a' + 10;
			else if (y >= 'A'&& y <= 'Z') y = y - 'A' + 10;
			else if (y >= '0' && y <= '9') y -= '0';

			plaintext[i][j] = x * 16 + y;
		}
	}
	
	corr = (double*)calloc(TraceLength, sizeof(double));
	Sx = (double*)calloc(TraceLength, sizeof(double));
	Sxx = (double*)calloc(TraceLength, sizeof(double));
	Sxy = (double*)calloc(TraceLength, sizeof(double));

	for (i = 0; i < TraceNum; i++)
	{
		for (j = startpt; j < endpt; j++)
		{
			Sx[j] += data[i][j];
			Sxx[j] += data[i][j] * data[i][j];
		}
	}

	for (int block = 0; block < 16 ; block++)
	{
		maxcorr = 0;
		maxkey = 0;
		for (key = 0 ; key < 256; key++)
		{
			Sy = 0;
			Syy = 0;
			memset(Sxy, 0, sizeof(double) * TraceLength);
			for (j = 0; j < TraceNum; j++) // hw 구하는 곳
			{
				iv = SBOX[plaintext[j][block] ^ key]; // 공격지점, 배열 인자 실수 조심
				hw_iv = 0;
				for (k = 0; k < 8; k++)
					hw_iv += ((iv >> k) & 1);
			
				Sy += hw_iv;
				Syy += hw_iv * hw_iv; // 오버플로우 방지 스카우트
				
				for (k = startpt; k < endpt; k++)
				{
					Sxy[k] += hw_iv * data[j][k];
				}

			}

			for (j = startpt; j < endpt; j++) // 상관계수 구하는 곳
			{
				a = (double)TraceNum * Sxy[j] - (Sx[j] * Sy);
				b = sqrt((double)TraceNum * Sxx[j] - (Sx[j] * Sx[j]));
				c = sqrt((double)TraceNum * Syy - (Sy * Sy));

				corr[j] = a / (b * c);
				if (fabs(corr[j]) > maxcorr)
				{
					maxkey = key;
					maxcorr = fabs(corr[j]);
				}
			}

			sprintf(buf, "%scorrtrace\\%02dth_block_%02d(%02x).corrtrace", DIR, block, key, key);
			wfp = fopen(buf, "wb");
			if (wfp == NULL)
			{
				printf("블록 쓰기 에러\n");
			}
			fwrite(corr, sizeof(double), TraceLength, wfp);
			fclose(wfp);
			printf(".");
			fflush(stdout);
		}
		printf("%d Block | KEY : %02x | CORR : %lf\n", block, maxkey, maxcorr);


	}
	free(plaintext);
	free(Sxy);
	free(Sx);
	free(Sxx);
	free(data);
	free(corr);


}