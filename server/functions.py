'''
Created on May 11, 2015

@author: niyohn
'''

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA


def decrypt(ciphertext, private_rsa_key):
    """Decrypts a message using PKCS1-OAEP with the private RSA key"""
   
    cipher = PKCS1_OAEP.new(private_rsa_key)
    message = cipher.decrypt(ciphertext)

    return message

def sign(message, private_rsa_key):
    """Signs a message using PKCS1-OAEP with the private RSA key"""
   
    hashed = SHA.new(message)
    signer = PKCS1_v1_5.new(private_rsa_key)
    signature = signer.sign(hashed)

    return signature

def get_RSA_key():
    rsa_key = \
    b'-----BEGIN RSA PRIVATE KEY-----\n\
    MIISKgIBAAKCBAEA3yA+JsfvcmhthnaVHp8zEsjJM4ShWLYRQd96Lx8BqpB9gICv\no8upZis\
    xHy4Wov3nIV/6mO7PnnSsM8jhtzEW/5cjSQ6XrC3PfjRHIYwUkBHFv8aJ\n2t5XeBgUgNqnXU\
    iNd1/fKCcTGQnMvL3fkmMA+jgWc6arasWcAMScMjUNp+rF5jpg\nNutWEV9vcObYmBnl2MamG\
    /FOEbeBZ5NIj4lqvWuefoRDypAsGrYfHhSF5CT5YjFu\nzXvc/ZxxZOHZ2ng+wlXNsGyff92e\
    Iq4vQNCLmjFihdCXi0LNNyD4tXykXwzd2tI0\n5vebYOULoVFSdQVgTxDtSVbEAIkQUk1JFYg\
    n74GZakt64E8yOmXdI+wNb+qYJKAA\n7jyGvLbzEmheJOxUz9GqkhKVCTNB8yoMFYRlVVnfi5\
    4volb/l+YWUCcZS/Ktxx/z\nFSVNrfh8UYlHiszIDOa5Hxv+5Egq20VRtOOeUJw2Ba2RB8UBT\
    wtTtWbEc0Dmz0Fd\nbSSXbFkKZyYiY86p7ZO0kC4t4c+3IxNdB/+3cLgvw4fupoVih8fxCd13\
    nofpfanj\niw2di6hvE4teTwgQqr+520WDOo0+EvHcLEsLgL59VBUdtEPfbWam0WLZJ2PirG3\
    q\nEayBMGi+PguAxFsb5RNyXL+nycJ27VpJtHvySEEVpSUMQpdYGKJLfAxA0BneqGLN\nDu/P\
    7b5x0E8vpIBZ98UFChhyrFs9f5d18qc6f03YjwK6q7+BQJ6/8Ayu0A4QQmyl\nFOLoJHfOEed\
    gCYuHpqr8Z2U3N1hdrJqCh3Ky1//6HLTKtLzhMsDaUNDbZs/sFWqM\nqoy+oh0lNNKGCimavK\
    J/DR4I8JspNCm/XZEfPRJ+aJYLvuY0VizS+X29raviLomd\nmlHN4s4L7cR0kt2m7O/iJLNpp\
    3SBEqUS6EL8AALa0BJ1hahVO8cvO4i6iCWxCYlo\nMXMfRba8r2O5GF5/N/NXesJxnR0rpz2M\
    8rxiLnl/BUMfiFPqacQt5TLOW0XdPtll\nQ7lQqGG5r286YoT/WQ7v60R3e3vIZ7+9QEs0V+F\
    yKVQ2RUL/nGYErSh4ce3poIhk\nr39Ps3eZTC9zs1+vgzNdTRwOkF9TKxJWe5vNPRBIytN9IS\
    FBN+tPh0GH/LqpYqpq\npdx3Pj3GHBdRdpmChL742beEpLDnS6ujuDDYseJznLJCqcEB6McqK\
    rkF371GUgb8\nvGdgMzUVDl3TdU6eAKgU0sRY+pCO4+AjGTS+TQ/PacOzyGEIB4K3gaQcRGcJ\
    ws9x\ndohvfITxYi/S3Uxhy2CYqZ9Murj68qhQGxYsqcBsAsgsOUWQFsOtZY5+e/bsTUl3\n7\
    Wqj3neCa5q6kP29kcIsa3TKGTPk4+XNMEBwwQIDAQABAoIEAQCnSLYwPzAPt6l9\n6YQNjFAv\
    YigvHt4U85PmrlUd5QJLzb66TEDi7fuYZQOUG+rO0sup4xqv9EPmyhSd\nUpufzAcxIzBKQs2\
    GQmZReYJm7W4xQZHgIUsTtCUiHfOpU8WtE4s0l8Vohjs0R3uf\nej+XsfB2qPx0Qt470+INVV\
    rB7bLKVSOAY/3kzvYdWk7j978l8iy4JN8/DeB5Ofqk\nG/GH5AAJ+hi/RAzLXuIiOK8Fz18+2\
    FW8v9ER8C6UWelOOGIsAIEVFF19S0MeC5rW\n5373+iLgPOxf5S7pMvFGxsqQzt0xgiUHPRh6\
    neN5duAMVzsaDyjQvqEYnhufRyPc\ngKMtqIJAeAr8fZCngdjnnZ15pC3C3cCpnOh1tR1TeVq\
    uT19eEW3YzZozoAjq9+oX\nFEwxCa0rm5EVTUjrToycZt4Nw/KcVVrictq93NTrfORAAUuJDd\
    Vijsz2PPgSUOUI\ntmT22LzGNQfvo9ybVaGQkK52z5Cz1FH3y0rvXELG8c7x3M5lw/j07QuwG\
    V8+8Iue\nmZLjP15Z/U2aLFzJrjFcGZRm0Asx6TYuh+PYSiH3JhX5MkFHwYU1bz853Vjw2hpS\
    \n+9AVyUHbiXXPR3GYyFZH4HFrhM/IT4QPwOx/ybSmBbG0NM2a6a/1RGo2jV6PzuN5\nOnsN/\
    Ot+LoW65hbWCj/7YBp1633gRk6YIWLch/9frW3u0PlxjQDKuY39TFO/DWCx\n4S0mL535HEKq\
    QMHVTlSojTsXMe9yEl2CFOMV2AdugM70f6e0TcKj2BnJrS/f75ko\n38XWZhSXiZo6FlFMU9o\
    ievxWbxOQ29QazaacZyF9i2uqKbuxtbs6sjqV+yL1pHns\nYm3QRwRzRNvf/xsKJwulWS5w8i\
    D5/g2BUN+ypMmW1VuBnJAJt2APZuTHpYL10RK3\nwiQ1MPuZ1J5CLCqOitjj5tHBA35Am5GFi\
    jJJLL2cyfq+pWxA0aZ5bsyiVBYN/587\ngQGOOWOTVy26CxKDdxQLSERrzdftlncrYXbp3oHy\
    AtHX8tjdQ/K/DiVK85USo246\nnHaAooggHCgOj8EiTySHhkoeaB4RrK8RKDd2fIXF7hGOPp7\
    d+FWLTP+gp+Xezu4W\n9/FS1gUM3bwDqdSWnNlWG0z3f6Q2VWhbiFZ96GINozG1r+33lsLeF2\
    aJkXQxdf2i\nd7YOx1E4s+7AVEElM14YKQGzulHCxS/2KAf8N6tm3KasY11i8YxdIBtMv4jaL\
    C6v\n3+zywboonYPbVP81tTOnV1hlJzfYA/zOGaMNV6Xa06t338/8zUsV20GNQqXq2wL3\n1d\
    wB6PcchfQg1AC4ZoLVk0c+FuBM9Zi2/fkAorDZA+qFi3vnEmijaLmk3JZuCgto\nbPT6llwBA\
    oICAQDryG64pmYFvgHSPE4G4dAuNYmS+qYiZe6tsuikI7x/tunlyFZ2\nwP88wlpOfDQCYL0E\
    8G1W66PHBJ3OCJApvpGGxjchPM4aOxhyht9KhKbeKEWZtQcD\nbIG3zYzMAJGCt9bdUjlst9L\
    FrrGYYAUcApx0jmpjza/VwVN9Jk6UbikuG7b7dNxC\n/w5uVBm5nR47hYoKxfJYcVmgv68gKL\
    YoUGe8TOTMXgE3k7DHIJEYk7NumutLI1ed\nmB3NmhuAEBMIuYoruGp4UTmqTZ1ueCwjAPYUa\
    R22fioY7NSppU+QxS20n+UM+RHF\nT7GwgVjWTUcjeowWaU6nyAJ6F0x7mVOfZCohQAUk+juq\
    OWYtDcIlcdxaSr3lL/QM\nLuujLn35iN9f9UNdnah9JEOeSEOAkAWSZnAF0IIJIlt2rG/MVYN\
    xVCrwAGO84ghP\nqa/X+PmLO16folPby4zmScn00W/WHs22o4I/wlPIWaYFXdJpyh23Is/yVk\
    6Rn7JY\n4FRLf+YE/y9HlVuupY9qTueQmYuEN/NyUE4WcC0BZ81x4saDQFRriVEV2iF6vt56\
    \nyj9NZ+4IexXxCWCdYVxbO08EHQwGdkLRtS9Q5EuOtLoVMJDPfpwtpbgegigjB51c\nQqV6P\
    EbC16OiGL0cUX9j64ChpoAuSoV2RBI44ItyaxaIaQ17/QEDQGuo4QKCAgEA\n8kH7c70WzCGs\
    +WD2GMSSaKqnkAOg2FX3GxIBIQ7IsjlUTbC0bIZDJsvLdIzi2yYc\nJd0VwpfqG+VYf/WXUQg\
    Qyvg0+MGB17NI088I90eAsLZitPTpjrpdER1G3DiWCFvy\ng5Cw+rdbuhTz+KGRrkOrPOz/Dd\
    H2NfknocvM2Wc+xy6YRXkkSiGe++pSj0KkeF3F\nN+CkD5uJrGA5vFuQ3Z71jjl+EQw5S+Wc7\
    cw6JcFLl6eVKAJ/NFdyCOLIgNjqDmwB\nsjDzIZAg/xZJ2yLcOiLxkTogGNMJCifiMflXksfr\
    FgGFnfp0DLe4sI0cLPq4D//F\nVYO2pk/iZVZdsLHlz9A3CD4ZN9fhaGeG6uT6T104yEAKWS/\
    VPNvrJxBKqa66Xzc0\nuex8NePmOtbEf4oujZC8EHGcLQ5qt5XM3+bpuM553NogG6JSenGq+7\
    6kOVUu63gL\nRJBlVATMSEJLLUg0uBpTQ3atdYeOK/ebOhb5XA/t6tfysHGY5V3CfvHueojIo\
    zUy\nc9uBFGoCoQYpxM73AJAKGABfBbNG3AneGZoKDvwNqvKyFAlgcy5YHZ+fWv0d2Uof\n/D\
    dmxkWBZXumtpU7nvfvF6YlgDQCieYcZ/rxpFKBq/I/eZUYREG3wk2kS54FdjkQ\n4iCca/jkS\
    RFMOENVoBGjMAH1ZCVROCUizVHTGn+SY+ECggIBAKuqI0rXA6KcozDQ\n7TI/iFWMbxyO1xRm\
    SG84uf5/ckc+Am9k++a8P1iaXCuWbDtq+VO2RLUrHPPSXZ5b\nR7LM56FLgWn2nkwkyHjhz4K\
    ur9tBUONHFNMeVhdfVWpV45tbg9lheyO3doKs3OqG\nxlGNaSHHapg9cg7cEZAlqsKQrfS/Au\
    tzOsagcn5LRuuIBDHr2QRc+EQCSvIpfTSZ\nz33shIppJY/RxWsUYXmpMVrGdrZJnpP3KFw6G\
    0DNOcZ0bZdFlt6cBxCQer6Ogdej\nMOdPVNqpaZOrqbS6AV9+Vz6dANjoLVjTomeYzVMn6Wkl\
    nGytVX8frr+jdII1ol6+\n1E5RHAdXWCeC9JvL7KNSyA6BJqCqmDVcQ3/3TWJigB+E0rVHmYN\
    4POrX009TZ6ob\nsaLUaC0jkPlbhWISy9bmT6vcTuKsNfGYU9rEPZ2tzOndENiC1DFLsssb4C\
    kZryYj\nCT03MKaBMoTFGIYBuCeDmzzx4Jqc0dlefvgMY/MQLIVo0aB5kuXF7nPE/P2ffR+H\
    \nqPyKkT/u7iV+0Opg5I088fnVYS7awNNgUhTuWUZfK8QK8X+rhycucpKNzMq+5zlx\nMtcB5\
    nArtwMwe+bflB8uHEFzzWiQ9O4EJkK810P2zMIhRCbJgi4y+9/g36dR1TNe\n2Gqxxt6YRY7J\
    fv9UFRg3rVwTtA6hAoICAQDUWW32B5tCF4qtlYZiM3w6bswt+mA1\nATV27xM6TOEzB/mTl/6\
    u2glmqmCOqyf2/LLTpbV7OvoktaYbk8StbKp7n5GfMs+D\nqU1/DA1J4800GMrw33USfN0zMT\
    x5sMgiT6aGGIBpY+vtcoxgNg+idwJUh1ESZiax\nLNLGigPn1Q48PeWPkB51NH9NRhpUJRBRy\
    bAjyK9GVwoYpMg3CPQ0ry+DGXYdr19R\n3dTuxIN7sLF4H5co2Pdzg+sbSt6BwqF3PslFzo5v\
    rwydTIY0pZvxAcxJhm+4EtPr\nqQYm0+8lZEP2qCLdVToAI9KqPyahbquEqqfoy2mA4qkKNug\
    tB+LvhA2ZFgW442xb\nvdOPdmLKymYJcckgYEND82ludmNb1SLcb2GyT06ZVkjq7nKTcSZZRL\
    L0nwFMpUR5\n478PzDK2oZZENpbKYkB1v8kmnfcJoldcY39M/F01hnciJ6oJ6S786WZuzkpBq\
    S6/\n72yLQLQXNIdRwTSj4Q8qjkL8T0jA88Ea/nhZAeFlaX8gcmyObPQp9BhE7Z5dOsYz\n/h\
    pGyrViaSH55H6f/ZAjpk3quY5PjWtqmgTragyWYzqHIBoEFU+LirxzOFnKxMws\n4B2qL1c8u\
    G2dsNxe0IfS3OAcWz5WYg9bj63y6K70HdjNC3KKJsuZYZxvamgU/njx\nA+w7mSu4IHbLQQKC\
    AgBH9WzJPuc5qiKLnrNt/Nz7UIleE45u+NXyGfA81N1pF/TA\nypTlqw/Ba7TBwdpUeH1djsU\
    q31nqxvtiYRP8CypaBaA7WLLACQn69xequosi9xGq\nf15H5OIWQqaWkC1BoTo5gJhohj6rGx\
    SdCwOPU/ypufCJbZ4qdHD8Qv66xxojIENM\n5IZpFV+uaPWPygHRkCwyOHTKRBGuDgH76/3Ay\
    qvnjZUMszHakvzf7L1xs0t9muAG\nAoi3y+KJ0lvdD7zwPn8KXM0JTIXnJPtlk8RohtyaHY42\
    Bz3hiCrSLS9lOMvom3fI\nGt0knodRexLHypJbWux5L1GhvsAojl6evslbKW/Yhmsey9dB4tl\
    NTrZBVW9Nb/hm\nApW2Ycht8Z/yM4ExDku/IPKAhhM4sGtRyLeQKZ19esSq6BSsSbZjomYoms\
    rIW+jY\nxb89VPY5v690Ojn5AD5cmEmPGVV89zOeQxcbOTphdo+0GmNc/tdIesub35uKCkt7\
    \n4Z6+hVmGe6BnjlIgs3w9E0GhAxDkXMNmjkaHPBkA9BWEpUN1d0sdcd0QAEWDrHA3\nkjvIM\
    cLw/Z+4yKAv8jGUBZ2t0Py045Ob4/6qODmkgi5tQjLyBqH+mUAI2S6ExTLj\n7KOdUM2S2XK/\
    8m89DS/IeGzoeHyBPS/NtH9tUMirKlm+ocIdUx5O5Sys3Gq1EQ==\
    \n-----END RSA PRIVATE KEY-----'
    
    return rsa_key