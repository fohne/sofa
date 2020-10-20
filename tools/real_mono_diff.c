#include <stdio.h>
#include <time.h>

/*
 * struct timespec {
        time_t   tv_sec;        //seconds 
        long     tv_nsec;       // nanoseconds 
   };

    CLOCK_REALTIME
    CLOCK_MONOTONIC
    CLOCK_PROCESS_CPUTIME_ID
    CLOCK_THREAD_CPUTIME_ID 
*/

int main()
{
    struct timespec ts;

    printf("Real, Mono\n");
    
    for (int i = 0; i < 100; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        printf("%ld.%ld\n",ts.tv_sec, ts.tv_nsec);
    }

    return 0;
}
