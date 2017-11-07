#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

/* returns packet id */


int host_name_cmp(unsigned char* buf,int size){
	
	int host_addr;//host name starting point in buf
	char host_name[100];//str for host name
        int str_len=0;//str_len for host_name

	char c; //char get from file
	char tmp[30]; //temp buf for host name 
	int toggle=0;
	int cnt=0;
	FILE * fp = fopen("top-1m.csv",'r');

	//find "host :"
        for(int i=0;i<size;i++){
		if(buf[i]==72&&i<size-10){
			if(buf[i+1]==111&&buf[i+2]==115&&buf[i+3]==116&&
			buf[i+4]==58&&buf[i+5]==32){
				//set host_addr
				host_addr=i+6;
				while(buf[host_addr]!=13){//\r = 0d = 13
					//put host name in host_name[] until \r
					host_name[str_len++]=buf[host_addr++];
				}
			}	
		}
        }

	//compare c and host_name
	while(1){
		//get c from "top-1m.csv" until EOF
		if((c=fgetc(fp))==EOF)break;
		//toggle that accept string from , to \n
		if(toggle==0){
			if(c==','){
				toggle=1;
				continue;
			}
		}
		if(toggle==1){
			if(c=='\n'){
				//add EOF at the end of tmp
				tmp[cnt]='\0';
				//compare string
				if(memcmp(host_name,tmp,str_len-1)==0){
					printf("You shall not pass !!! %s\n",host_name);
					return 1; //DROP
				}
				//initialize
				cnt=0;toggle=0;continue;
			}
			tmp[cnt++]=c;
		}
	}
	return 0;//ACCEPT
}


static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;
	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d ", ret);
	}
	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int ret;
	unsigned char* tmp_data;

	u_int32_t id = print_pkt(nfa);
	ret=nfq_get_payload(nfa,&tmp_data);
	// if input == host name then drop
	if(host_name_cmp(tmp_data,ret)==1){
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	// else accept
	else return nfq_set_verdict(qh, id, NF_ACCEPT,0,NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
