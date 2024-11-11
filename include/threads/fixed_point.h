#define F (1 << 14)
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

// int 형 정수 ->고정 소수점 형식으로 반환
int int_to_fp(int n){
  return n * F;
}
// 고정 수수점 -> 정수로 변환
int fp_to_int (int x){
  return x / F;
}
// 고정 소수점 -> 반올림 -> 정수로 변환
int fp_to_int_round (int x){
  if (x>=0) 
    return (x+F/2)/F;
  else
    return (x-F/2)/F;
}
// 두 고정 소수점 값 더하기
int add_fp (int x, int y){
  return x + y;
}
// 두 고정 소수점 값 빼기
int sub_fp (int x, int y){
  return x - y;
}
// 고정 소수점 값 + 정수 값
int add_mixed (int x, int n){
  return x + n * F;
}

int sub_mixed(int x, int n) {
  return x - n * F;
}

// 두 고정 소수점 값 나누기
int mult_fp (int x, int y){
  return ((int64_t) x) * y / F;
}
// 고정 소수점 값 * 정수 값
int mult_mixed (int x, int n){
  return x * n;
}
// 두 고정 소수점 값 나누기
int div_fp (int x, int y){
  return ((int64_t) x) * F / y;
}
// 고정 소수점 값 / 정수 깂
int div_mixed (int x, int n) {
  return x / n;
}