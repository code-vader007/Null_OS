

#include <stdint.h>
#include "mousesupport.h"
#include "mousesyscall.h"
#include "game.h"

/* screen writing routines  - defined in vga.c */
extern void init_screen();
extern void write_char(char, int x, int y);
extern void write_string(char*, int x, int y);
extern void clear_screen();

/* Static data */
int rtc_fd = -1;		// RTC file descriptor
int rng_fd = -1;		// RNG file descriptor
int tux_fd = -1;		// Tux Controller file descriptor
int mouse_fd = -1;		// Mouse file descriptor

int fired = 0;		/* Count of user-fired missiles */
int score = 0;		/* score, as reported by ioctl(GETSTATUS) */
int bases_left = 0;	/* number of bases remaining */

/* This command_t enum encodes the input keys we care about */
typedef enum { NOKEY, QUIT, LEFT, RIGHT, UP, DOWN, FIRE } command_t;

int rand() {
	int ret;
	if(-1 == ece391_read(rng_fd, &ret, sizeof(int))) {
		return 0;
	}
	return ret;
}

/* get_command_tux()
 * Checks if a meaningful key on Tux was pressed, and returns it;
 */
command_t get_command_tux() {
	static command_t tux_mapping[8] = {FIRE, LEFT, FIRE, RIGHT, UP, DOWN, LEFT, RIGHT};
	static uint8_t tux_allow_long_press[8] = {0, 1, 0, 1, 1, 1, 1, 1};
	static uint8_t prev_status = 0;

	// After game start, START button quits game
	if(bases_left) tux_mapping[0] = QUIT;

	// Get key from Tux Controller
	uint8_t status;
	if(-1 == ece391_read(tux_fd, &status, sizeof(uint8_t))) {
		return NOKEY;
	}

	int i;
	for(i = 0; i < 8; i++) {
		if(status & (1 << i)) {
			// Long press fire detection
			if(!tux_allow_long_press[i] && (prev_status & (1 << i))) continue;
			prev_status = status;
			return tux_mapping[i];
		}
	}

	prev_status = status;
	return NOKEY;
}

/* get_command_mouse()
 * Checks if a meaningful move on mouse was done, and returns it;
 */
command_t get_command_mouse(int16_t* dx, int16_t* dy) {
	int32_t buf[4];
	static uint8_t is_fire_pressed = 0;
	if(-1 == ece391_read(mouse_fd, buf, 4 * sizeof(int32_t))) {
		return NOKEY;
	}

	*dx += buf[0] / 2;
	*dy -= buf[1] / 2;

	if(buf[2]) {
		if(!is_fire_pressed) {
			is_fire_pressed = 1;
			return FIRE;
		} else {
			return NOKEY;
		}
	} else {
		is_fire_pressed = 0;
		return NOKEY;
	}
}

/* get_command()
 * Checks if a meaningful key was pressed, and returns it;
 */
command_t get_command(int16_t* dx, int16_t* dy) {
	command_t ret = get_command_tux();
	switch(ret) {
		case LEFT: *dx = -1; *dy = 0; break;
		case RIGHT: *dx = 1; *dy = 0; break;
		case UP: *dx = 0; *dy = -1; break;
		case DOWN: *dx = 0; *dy = 1; break;
		default: *dx = 0; *dy = 0; break;
	}
	if(FIRE == get_command_mouse(dx, dy)) ret = FIRE;
	return ret;
}

/* make_missile()
 * Wrapper around the ioctl() to add a missile to the game.
 */
void make_missile(int sx, int sy, int dx, int dy, char c, int vel)
{
	struct missile m[1];
	int vx, vy, mag;

	m->x = (sx<<16) | 0x8000;
	m->y = (sy<<16) | 0x8000;

	m->dest_x = dx;
	m->dest_y = dy;

	vx = (dx - sx);
	vy = (dy - sy);

	int abs_vx = (vx > 0) ? vx : -vx;
	int abs_vy = (vy > 0) ? vy : -vy;
	mag = (abs_vx > abs_vy ? abs_vx : abs_vy) << 8;
	if(mag == 0) mag = 1 << 8;
	m->vx = ((vx<<16)*vel)/mag;
	m->vy = ((vy<<16)*vel)/mag;

	m->c = c;
	m->exploded = 0;

	if(-1 == mp1_ioctl((unsigned long)m, RTC_ADDMISSILE)) {
		ece391_fdputs(1, (uint8_t*) "add missile failed\n");
	}
}

/* update_crosshairs()
 * move the crosshairs via the ioctl()
 */
void update_crosshairs(command_t cmd, int16_t dx, int16_t dy){
	if(crosshairs_x + dx > 79) dx = 79 - crosshairs_x;
	if(crosshairs_x + dx < 0) dx = 0 - crosshairs_x;
	if(crosshairs_y + dy > 24) dy = 24 - crosshairs_y;
	if(crosshairs_y + dy < 0) dy = 0 - crosshairs_y;

	if((dx != 0) || (dy != 0)){
		unsigned long d;

		d = (unsigned long)dx&0xFFFF;
		d |= ((unsigned long)dy&0xFFFF)<<16;

		mp1_ioctl(d, RTC_MOVEXHAIRS);
	}

	switch(cmd){
	    case FIRE:
			make_missile(79, 24, crosshairs_x, crosshairs_y, '*', 200);
			fired++;
	    default:
			break;
	}

}

void mp1_notify_user(int foobar){
	unsigned long status_word;
	if(!mp1_ioctl((unsigned long) &status_word, RTC_GETSTATUS)){
		score = status_word&0xFFFF;
		bases_left = ((status_word>>16)&1) + ((status_word>>17)&1)
				+ ((status_word>>18)&1);
	}
}

void draw_centered_string(char *s, int y){
	write_string(s, (80-ece391_strlen((uint8_t*) s))/2, y);
}

#define DCS(str) draw_centered_string( str , line++)

void draw_starting_screen(){
	int line = 5;
	clear_screen();
	DCS("                       MISSILE COMMAND                          ");
	DCS("                          Commands:                             ");
	DCS("               space ................. fire missile             ");
	DCS("          arrow keys ................. move crosshairs          ");
	DCS("             h,j,k,l ................. move crosshairs (vi-style");
	DCS("        ` (backtick) ................. exit the game            ");
	DCS("                                                                ");
	DCS("                                                                ");
	DCS("   Protect your bases by destroying the enemy missiles (e's)    ");
	DCS("   with your missiles. You get 1 point for each enemy           ");
	DCS("   missile you destroy. The game ends when your bases are all   ");
	DCS("   dead or you hit the ` key.                                   ");
	DCS("                                                                ");
	DCS("               Press the space bar to continue.                 ");
}

void draw_status_bar(){
	char buf[80] = "[score    ] [fired    ] [accuracy    %]";
	int percent = fired ? (100*score)/fired : 0;

	ece391_itoa(score, (uint8_t*) (buf + (score >= 100 ? 7 : (score >= 10 ? 8 : 9))), 10);
	buf[10] = ']';
	ece391_itoa(fired, (uint8_t*) (buf + (fired >= 100 ? 19 : (fired >= 10 ? 20 : 21))), 10);
	buf[22] = ']';
	ece391_itoa(percent, (uint8_t*) (buf + (percent >= 100 ? 34 : (percent >= 10 ? 35 : 36))), 10);
	buf[37] = '%';

	ece391_status_msg(buf, 80, 0x02);
	// write_string(buf, 0, 0);
}

static struct missile malloc_missiles[1000];

void* mp1_malloc(int size) {
	int i;
	for(i = 0; i < 1000; i++) {
		if(!malloc_missiles[i].c) {
			return (void*) &(malloc_missiles[i]);
		}
	}
	return (void*) 0;
}

void mp1_free(void* ptr) {
	ece391_memset(ptr, 0, sizeof(struct missile));
}

int main(){
	command_t cmd;

	mp1_ioctl(0, RTC_STARTGAME);
	rng_fd = ece391_open((uint8_t*) "rng");
	rtc_fd = ece391_open((uint8_t*) "rtc");
	tux_fd = ece391_open((uint8_t*) "tux");
	mouse_fd = ece391_open((uint8_t*) "mouse");
	int rtc_interval = 32;
	ece391_write(rtc_fd, &rtc_interval, sizeof(int));

	/* On with the game! */
	draw_starting_screen();
	int16_t dx = 0, dy = 0;
	while(FIRE != get_command(&dx, &dy));
	clear_screen();

	bases_left = 3;

	while(bases_left && QUIT != (cmd = get_command(&dx, &dy))) {
		draw_status_bar();
		update_crosshairs(cmd, dx, dy);
		mp1_rtc_tasklet();
		ece391_read(rtc_fd, (void*) 0, 0);

		if(rand() % 127 == 0) {
			make_missile(rand()%80, 0, 20*(rand()%3+1), 24, 'e', rand()%5 + 10);
		}
	}

	draw_centered_string("+------------+", (25/2)-1);
	draw_centered_string("| Game over. |",  25/2);
	draw_centered_string("+------------+", (25/2)+1);

	ece391_close(rng_fd);
	ece391_close(rtc_fd);
	ece391_close(tux_fd);
	ece391_close(mouse_fd);

	return 0;
}
