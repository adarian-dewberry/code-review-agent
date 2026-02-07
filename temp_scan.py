
def access_customer_pii(customer_id):
    customer = Customer.objects.get(id=customer_id)
    return customer.email
