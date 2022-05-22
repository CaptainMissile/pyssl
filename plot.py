import matplotlib.pyplot as plt


# cfb
n_bit1 = [16,64,96,128,256]
t1 = [0.0025207996368408203, 0.002365589141845703, 0.001989603042602539, 0.0015017986297607422, 0.0016164779663085938]

# ecb
n_bit2 = [16,64,96,128,256]
t2 = [0.0006618499755859375, 0.0032227039337158203, 0.0022106170654296875, 0.0028007030487060547, 0.0025501251220703125]

#rsa
n_bit3 = [1024,1536,2048,2560,3072]
t3 = [0.6984107494354248, 0.8505840301513672, 0.6387746334075928, 2.1576459407806396, 2.4252915382385254]

# plt.xlabel('no of bits')
# plt.ylabel('times (s}')
# plt.plot(n_bit1,t1, label = "CFB")
# plt.plot(n_bit2, t2, label = "ECB")
# plt.legend()
# plt.show()

plt.title('RSA')
plt.xlabel('no of bits')
plt.ylabel('times (s}')
plt.plot(n_bit3,t3, label = "RSA")
plt.legend()
plt.show()
