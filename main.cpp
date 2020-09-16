#include "proxy.h"
#include "router.h"

int main(int argc,char** argv)
{
    
    if(argc!=2)
    {
	   printf("./hw1 config_file\n");
	   exit(1);
    }
    char *config_fn=argv[1];
    CProxy proxy; 
    if(!proxy.initialize_configure(config_fn))
	   exit(1);
    
    if(!proxy.get_all_interface_info())
	   exit(1);
   
    if(!proxy.initialize_socket())
	   exit(1);

    char tun_fn[IFNAMSIZ] = "tun1";
    int flags = IFF_TUN;

    /*
     * open tun for reading and writing.
     */
    if(!proxy.initialize_tun(tun_fn, flags | IFF_NO_PI))
	exit(1);

    //proxy.generate_random_path();
    //printf("msg size: %d\n",sizeof(struct cc_ext_msg));
 
    int pid;
    if((pid=fork())==0)
    {
	   proxy.run();
	   exit(0);
    }


    /*
     * proxy to fork routers.
     */
    proxy.fork_router();
    return 0;
}
