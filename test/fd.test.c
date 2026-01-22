#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#define TESTDIR "../testdir"
#define FILEPERM 0666
#define DIRPERM 0755

int test_1(const char* path) {
    int fd_init = open(path, O_CREAT|O_TRUNC|O_RDWR, 0644);

    if (fd_init < 0) {
        perror("open init");

        return -1;
    }

    close(fd_init);

    // fd1 and fd2 should keep independent offset
    int fd1 = open(path, O_RDWR);

    int fd2 = open(path, O_RDWR);

    if (fd1 < 0 || fd2 < 0) {
        perror("open");

        return -1;
    }

    // both start at offset 0
    if (write(fd1, "A", 1) != 1) { 
        perror("write fd1"); 
        
        return -1;
    }

    // this write should write over from offset 0 again since fd2 keep a separated offset
    if (write(fd2, "B", 1) != 1) { 
        perror("write fd2"); 

        return -1;
    }

    close(fd1); 

    close(fd2);

    int fd = open(path, O_RDONLY);

    char buf[2] = {0};

    if (read(fd, buf, 1) != 1) {
        perror("read");

        return -1;
    }

    close(fd);

    // Expected: "B" because fd2 wrote at offset 0, overwriting A.
    printf("%c\n", buf[0]);

    if (buf[0] != 'B') {
        return -1;
    }

    return 0;
}

int test_2(const char* path) {
    int fd = open(path, O_CREAT|O_TRUNC|O_RDWR, 0644);

    if (fd < 0) {
        perror("open");

        return -1;
    }

    int fd2 = dup(fd);
    if (fd2 < 0) {
        perror("dup");

        return -1;
    }

    if (write(fd,  "A", 1) != 1) {
        perror("write fd");

        return -1;
    }

    if (write(fd2, "B", 1) != 1) {
        perror("write fd2");

        return -1;
    }

    lseek(fd, 0, SEEK_SET);

    char buf[3] = {0};

    if (read(fd, buf, 2) != 2) {
        perror("read");

        return -1;
    }

    printf("%s\n", buf); // expects "AB"

    close(fd2);

    close(fd);

    if (strcmp(buf, "AB") != 0) {
        return -1;
    }

    return 0;
}

/**
 * Test whether the file system can handle open file descriptors correctness
 */
int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);

        return 2;
    }

    if (test_1(argv[1]) < 0) {
        printf("=> Test 1 failed\n\n");
    } else {
        printf("=> Test 1 succeed\n\n");
    }

    if (test_2(argv[1]) < 0) {
        printf("=> Test 2 failed\n\n");
    } else {
        printf("=> Test 2 succeed\n\n");
    }

    return 0;
}