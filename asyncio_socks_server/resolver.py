
import dns.resolver

def query(my_resolver, name, query_type):
    answers = my_resolver.query(name, query_type)
    for rdata in answers: 
        return rdata.to_text()

