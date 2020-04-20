/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
 * Copyright (C) 2015-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef ISOLATE_H
# define ISOLATE_H


void init_fd_limits_default(struct main_server_st * s);

/* Adjusts the file descriptor limits for the main or worker processes
 */
void update_fd_limits(struct main_server_st * s, unsigned main);

void set_self_oom_score_adj(struct main_server_st * s);

void drop_privileges(struct main_server_st * s);

#endif