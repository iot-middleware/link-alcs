#ifndef ALCS_TIMER_H
#define ALCS_TIMER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*alcs_timer_cb)(void *);

int alcs_timer_init ();
void alcs_timer_deinit ();
void *alcs_timer_create(const char *name, alcs_timer_cb func, void *user_data);
int alcs_timer_start(void *timer, int ms);
int alcs_timer_stop(void *timer);
int alcs_timer_delete(void *timer);

#ifdef __cplusplus
}
#endif
#endif /* ALCS_TIMER */
