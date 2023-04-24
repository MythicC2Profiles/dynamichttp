FROM itsafeaturemythic/mythic_base_image:0.0.2

RUN pip3 install mythic-container==0.2.0rc25
RUN pip3 install sanic==22.8.0
RUN pip3 install requests

WORKDIR /Mythic/

CMD ["python3", "main.py"]