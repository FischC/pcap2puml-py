"""
The purpose of this module is to create puml.SeqDiag objects out of PCAP files
To do so, it provides templates to ease such task:
	- VoipTemplate class: creates a puml.SeqDiag object out of a list of PCAP packets as parsed by pyshark

"""
from __future__ import print_function
try:
	import itertools.ifilter as filter
except ImportError:
	pass
try:
	import itertools.imap as map
except ImportError:
	pass
from pcap2puml import puml
import re
from collections import defaultdict

def has_layer(packet, layer_name):
    return layer_name in map(lambda layer: layer._layer_name, packet.layers)

class VoipTemplate(object):
	'''
	This is a template to create ,
	which we can use to create a a puml.SeqDiag object out of a list of PCAP packets as parsed by pyshark
	'''
	def __init__(self, nodealiases={}, sipfields=[], body4methods=[]):
		self.__call_ids = {}
		self.nodealiases = nodealiases
		self.sipfields = sipfields
		self.body4methods = body4methods

	CALL_ID_COLORS = ['red', 'blue', 'green', 'purple', 'brown', 'magenta', 'aqua', 'orange']

	def get_message_color(self, packet):
		call_id = packet.sip.get_field('call_id')
		call_id_index = self.__call_ids.get(call_id)
		if(call_id_index == None):
			call_id_index = len(self.__call_ids)
			self.__call_ids[call_id] = call_id_index
		return VoipTemplate.CALL_ID_COLORS[call_id_index % len(VoipTemplate.CALL_ID_COLORS)]

	def participantid_to_participantname(self, participantid):
		participantname = self.nodealiases.get(participantid)
		if(participantname == None):
			participantname = participantid
		return participantname

	def get_transport_ports(self, packet):
		if(has_layer(packet, 'udp')):
			t_layer = packet.udp
		elif (has_layer(packet, 'tcp')):
			t_layer = packet.tcp
		elif (has_layer(packet, 'sctp')):
			t_layer = packet.sctp
		else:
			raise ValueError('packet contains no transport layer')
		return (t_layer.srcport, t_layer.dstport)
	
	def get_participant_ids(self, packet):
		src_ip = packet.ip.src
		dst_ip = packet.ip.dst
		return (src_ip, dst_ip)

	def get_participants(self, packet):
		(src_id, dst_id) = self.get_participant_ids(packet)
		src = {'name': '"{}"'.format(self.participantid_to_participantname(src_id))}
		dst = {'name': '"{}"'.format(self.participantid_to_participantname(dst_id))}
		return (src, dst)

	def get_arrow(self, packet):
		arrow = {'head': '>', 'shaft': '-', 'color': self.get_message_color(packet)}
		return arrow

	def get_sequence_number(self, packet):
		return {'number': packet.number}

	def get_timestamp(self, packet):
		return packet.sniff_timestamp

	def parse_all_sip_headers(self,header_string):
		# Match "Header-Name: value" up to next header or end of string
		pattern = r'(\b[\w\-]+):\s*(.*?)(?=\s+[\w\-]+:\s|$)'
		matches = re.findall(pattern, header_string)
		return [(key.strip(), value.strip()) for key, value in matches]

	def add_content(self,sip):
		body_text = "<<<empty>>>"
		if hasattr(sip, 'msg_body'):
			hex_body = sip.msg_body.replace(':', '')
			try:
				body_bytes = bytes.fromhex(hex_body)
				body_text = body_bytes.decode('utf-8', errors='replace')
				body_text = re.sub(r'\r\n?$','', body_text)
				body_text = re.sub(r'\r\n?',r'\\n', body_text)				
			except Exception as e:
				pass
		return ('\nnote right: ' + body_text)

	def get_message_lines(self, packet):
		sip = packet.sip
		if(sip.get_field('status_code') == None):
			main_line = {'text': sip.get_field('request_line'), 'color': self.get_message_color(packet)}
		else:
			 main_line = {'text': sip.get_field('status_line'), 'color': self.get_message_color(packet)}
		message_lines = [main_line]
		sip_fields = ['call_id', 'from_user', 'to_user', 'p_asserted_identity', 'sdp_connection_info', 'sdp_media']
		all_headers = self.parse_all_sip_headers(sip.msg_hdr);
		if(self.sipfields!=None):
			sip_fields = sip_fields + self.sipfields
		for sip_field in sip_fields:			
			field_value = sip.get_field(sip_field)
			if(field_value != None):
				line_text = '{}: {}'.format(sip_field, field_value)
				message_lines.append({'text': line_text})
			else:
				for key, value in all_headers:
					if(key==sip_field):
						line_text = '{}: {}'.format(key, value)
						message_lines.append({'text': line_text})
		sdp_media_attrs = sip.get_field('sdp_media_attr')
		if(sdp_media_attrs != None):
			for sdp_media_attr in sdp_media_attrs.all_fields:
				if(sdp_media_attr.showname_value in ['sendrecv', 'sendonly', 'recvonly', 'inactive']):
					line_text = sdp_media_attr.showname
					message_lines.append({'text': line_text})

		if hasattr(packet.sip, 'Method'):
			for value in self.body4methods:
				if(packet.sip.Method==value):
					message_lines.append({'text': self.add_content(packet.sip)})

		return message_lines

	def packet_to_seqevents(self, packet):
		seqevent = puml.SeqEvent(
			self.get_participants(packet),
			self.get_message_lines(packet),
			arrow=self.get_arrow (packet),
			timestamp=self.get_timestamp(packet),
			sequence_number=self.get_sequence_number(packet),
			notes=None,
			event_type=puml.SEQEVENT_TYPE_MESSAGE)
		return [seqevent]

	def packets_to_seqevents(self, packets):
		seqevents = []
		supported_packets = filter(lambda packet: has_layer(packet, 'sip'), packets)
		for packet in supported_packets:
			for seqevent in self.packet_to_seqevents(packet):
				seqevents.append(seqevent)
		return seqevents

	def create_puml_seq_diagram(self, packets):
		seqevents = self.packets_to_seqevents(packets)
		participants = None
		return puml.SeqDiagram(seqevents, participants=participants)
