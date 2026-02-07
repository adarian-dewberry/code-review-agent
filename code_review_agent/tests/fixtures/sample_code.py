"""
Sample code for testing code review agent.

Contains intentional vulnerabilities for test cases.
"""

# Security vulnerabilities
sql_injection_vulnerable = """
def get_user(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return db.execute(query)
"""

prompt_injection_vulnerable = """
def review_contract(contract_text):
    prompt = f"Review this contract: {contract_text}"
    return llm.generate(prompt)
"""

# Compliance issues
missing_audit_log = """
def access_customer_email(customer_id):
    customer = Customer.objects.get(id=customer_id)
    return customer.email
"""

# Logic bugs
null_pointer = """
def process_items(items):
    total = 0
    for item in items:
        total += item.price  # Crashes if item is None
    return total
"""

# Performance issues
n_plus_one_query = """
def get_contracts_with_vendors(contract_ids):
    contracts = Contract.objects.filter(id__in=contract_ids)
    results = []
    for contract in contracts:
        vendor = Vendor.objects.get(id=contract.vendor_id)  # N+1!
        results.append((contract, vendor))
    return results
"""
