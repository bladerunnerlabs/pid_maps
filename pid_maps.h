#ifndef _PID_MAPS_H
#define _PID_MAPS_H

int pid_map_create(pid_t pid_nr);
int pid_map_update(pid_t pid_nr);
int pid_map_delete(pid_t pid_nr);

#endif