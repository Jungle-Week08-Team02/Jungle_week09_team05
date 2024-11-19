#ifndef __LIB_SYSCALL_NR_H
#define __LIB_SYSCALL_NR_H

/* 시스템 콜 번호 */
enum {
	/* 프로젝트 2 이상 */
	SYS_HALT,                   /* 운영체제를 중지합니다. */
	SYS_EXIT,                   /* 현재 프로세스를 종료합니다. */
	SYS_FORK,                   /* 현재 프로세스를 복제합니다. */
	SYS_EXEC,                   /* 현재 프로세스를 전환합니다. */
	SYS_WAIT,                   /* 자식 프로세스가 종료될 때까지 대기합니다. */
	SYS_CREATE,                 /* 파일을 생성합니다. */
	SYS_REMOVE,                 /* 파일을 삭제합니다. */
	SYS_OPEN,                   /* 파일을 엽니다. */
	SYS_FILESIZE,               /* 파일의 크기를 얻습니다. */
	SYS_READ,                   /* 파일로부터 읽습니다. */
	SYS_WRITE,                  /* 파일에 씁니다. */
	SYS_SEEK,                   /* 파일 내 위치를 변경합니다. */
	SYS_TELL,                   /* 파일 내 현재 위치를 보고합니다. */
	SYS_CLOSE,                  /* 파일을 닫습니다. */

	/* 프로젝트 3과 선택적으로 프로젝트 4 */
	SYS_MMAP,                   /* 파일을 메모리에 매핑합니다. */
	SYS_MUNMAP,                 /* 메모리 매핑을 제거합니다. */

	/* 프로젝트 4 전용 */
	SYS_CHDIR,                  /* 현재 디렉토리를 변경합니다. */
	SYS_MKDIR,                  /* 디렉토리를 생성합니다. */
	SYS_READDIR,                /* 디렉토리 항목을 읽습니다. */
	SYS_ISDIR,                  /* fd가 디렉토리를 나타내는지 테스트합니다. */
	SYS_INUMBER,                /* fd에 대한 inode 번호를 반환합니다. */
	SYS_SYMLINK,                /* fd에 대한 inode 번호를 반환합니다. */

	/* 프로젝트 2 추가 기능 */
	SYS_DUP2,                   /* 파일 디스크립터를 복제합니다 */

	SYS_MOUNT,
	SYS_UMOUNT,
};

#endif /* lib/syscall-nr.h */
