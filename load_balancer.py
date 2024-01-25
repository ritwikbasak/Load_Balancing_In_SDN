import random

class Load_Balancer:
    selected_server = None
    no_of_servers = None
    def __init__(self, selected_server, no_of_servers) -> None:
        self.selected_server = selected_server
        self.no_of_servers = no_of_servers
    
    def get_server(self, server_loads : dict, link_utilization : list, no_of_servers : int):
        # update selected server
        self.no_of_servers = no_of_servers
        self.least_server_load(server_loads)
        return self.selected_server
    
    def least_loaded(self, throughput_list : list):
        print("recieved the throughput list")
        if throughput_list:
            self.selected_server=throughput_list.index(min(throughput_list))+1
        print(f'Selected Server={self.selected_server}')

    def round_robin(self):
        if self.selected_server == self.no_of_servers:
            self.selected_server = 1
        else:
            self.selected_server += 1
        print(f'Selected Server={self.selected_server}')

    def random(self):
        self.selected_server = random.randint(1, self.no_of_servers)
        print(f'Selected Server={self.selected_server}')
    
    def dwrs(self,server_loads: dict):
        if server_loads:
            total_weight=sum(server_loads.values())
            print("Dictionary :")
            print(server_loads)
            print(f"Total Weight :{total_weight}")
            R=random.uniform(1,total_weight)
            print(f"Random number selected {R}")
            V=0
            for server,weight in server_loads.items():
                V=V+weight
                if V>=R:
                    self.selected_server=int(str(server)[1])
                    print(f"Server Selected after dwrs : {self.selected_server}")
                    break
    
    def least_server_load(self,server_loads: dict):
        if server_loads:
            print(f"Server Load Dictionary: \n {server_loads}")
            self.selected_server=int(min(server_loads, key=server_loads.get)[1])
            print(f"Server with least load = h{self.selected_server}")
    
    def High_SL_LL_ratio(self,server_loads: dict,link_utilization : list):
        if link_utilization:
            pass




            


    
