/*
 * Copyright (C) 2005-2008 Jive Software. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.openfire.plugin;

import org.dom4j.Element;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.interceptor.InterceptorManager;
import org.jivesoftware.openfire.interceptor.PacketInterceptor;
import org.jivesoftware.openfire.interceptor.PacketRejectedException;
import org.jivesoftware.openfire.privacy.PrivacyList;
import org.jivesoftware.openfire.privacy.PrivacyListManager;
import org.jivesoftware.openfire.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.*;

import java.io.File;
import java.util.*;

/**
 * @author <a href="mailto:xhdhr2007@126.com">xhdhr10000</a>
 */
public class PrivacyItemWildcardPlugin implements Plugin, PacketInterceptor {
    private static final Logger Log = LoggerFactory.getLogger(PrivacyItemWildcardPlugin.class);
    private PrivacyListManager privacyListManager;

    public PrivacyItemWildcardPlugin() {
        this.privacyListManager = PrivacyListManager.getInstance();
    }

    public void initializePlugin(PluginManager manager, File pluginDirectory) {
        InterceptorManager.getInstance().addInterceptor(this);
    }

    public void destroyPlugin() {
        InterceptorManager.getInstance().removeInterceptor(this);
    }

    public void interceptPacket(Packet packet, Session session, boolean incoming, boolean processed) throws PacketRejectedException {
        Log.debug("interceptPacket");
        Element element = packet.getElement();
        if (!incoming && element.getQualifiedName() == "message") {
            JID to = packet.getTo();
            PrivacyList list = this.privacyListManager.getPrivacyList(to.getNode(), "forbid");
            Element listElement = list.asElement();
            for (Element itemElement : listElement.elements()) {
                PrivacyItem item = new PrivacyItem(itemElement);
                if (item.matchesCondition(packet, to) && !item.isAllow()) {
                    Log.debug("PrivacyItemWildcardPlugin: Packet was blocked: " + packet);
                    throw new PacketRejectedException();
                }
            }
        }
    }




    static class PrivacyItem {

        private int order;
        private boolean allow;
        private Type type;
        private JID jidValue;
        private boolean filterEverything;
        private boolean filterIQ;
        private boolean filterMessage;
        private boolean filterPresence_in;
        private boolean filterPresence_out;

        PrivacyItem(Element itemElement) {
            this.allow = "allow".equals(itemElement.attributeValue("action"));
            this.order = Integer.parseInt(itemElement.attributeValue("order"));
            String typeAttribute = itemElement.attributeValue("type");
            if (typeAttribute != null) {
                this.type = Type.valueOf(typeAttribute);
                // Decode the proper value based on the rule type
                String value = itemElement.attributeValue("value");
                if (type == Type.jid) {
                    // Decode the specified JID
                    this.jidValue = new JID(value);
                }
            }
            // Set what type of stanzas should be filters (i.e. blocked or allowed)
            this.filterIQ = itemElement.element("iq") != null;
            this.filterMessage = itemElement.element("message") != null;
            this.filterPresence_in = itemElement.element("presence-in") != null;
            this.filterPresence_out = itemElement.element("presence-out") != null;
            if (!filterIQ && !filterMessage && !filterPresence_in && !filterPresence_out) {
                // If none was defined then block all stanzas
                filterEverything = true;
            }
        }

        /**
         * Returns true if the packet to analyze matches the condition defined by this rule.
         * Variables involved in the analysis are: type (e.g. jid, group, etc.), value (based
         * on the type) and granular control that defines which type of packets should be
         * considered.
         *
         * @param packet the packet to analyze if matches the rule's condition.
         * @param userJID the JID of the owner of the privacy list.
         * @return true if the packet to analyze matches the condition defined by this rule.
         */
        boolean matchesCondition(Packet packet, JID userJID) {
            return matchesPacketSenderCondition(packet, userJID) &&
                    matchesPacketTypeCondition(packet, userJID);
        }

        boolean isAllow() {
            return allow;
        }

        private boolean matchesPacketSenderCondition(Packet packet, JID userJID) {
            if (type == null) {
                // This is the "fall-through" case
                return true;
            }
            boolean isPresence = packet.getClass().equals(Presence.class);
            boolean incoming = true;
            if (packet.getFrom() != null) {
                incoming = !userJID.toBareJID().equals(packet.getFrom().toBareJID());
            }
            boolean matches = false;
            if (isPresence && !incoming && (filterEverything || filterPresence_out)) {
                // If this is an outgoing presence and we are filtering by outgoing presence
                // notification then use the receipient of the packet in the analysis
                matches = verifyJID(packet.getTo());
            }
            if (!matches && incoming &&
                    (filterEverything || filterPresence_in || filterIQ || filterMessage)) {
                matches = verifyJID(packet.getFrom());
            }
            return matches;
        }

        private boolean verifyJID(JID jid) {
            if (jid == null) {
                return false;
            }
            if (type == Type.jid) {
                if (jidValue.getNode() != null && jidValue.getResource() != null) {
                    // Rule is filtering by exact resource match
                    // (e.g. <user@domain/resource>)
                    return jid.equals(jidValue);
                }
                else if (jidValue.getResource() != null) {
                    // Rule is filtering by resource match
                    // (e.g. <domain/resouce>)
                    return jid.getDomain().equals(jidValue.getDomain()) &&
                        jid.getResource().equals(jidValue.getResource());
                }
                else if (jidValue.getNode() != null) {
                    // Rule is filtering by any resource matches (e.g. <user@domain>)
                    return jid.toBareJID().equals(jidValue.toBareJID());
                }
                else {
                    // Rule is filtering by domain (e.g. <domain>)
                    return jid.getDomain().equals(jidValue.getDomain());
                }
            }
            return false;
        }

        private boolean matchesPacketTypeCondition(Packet packet, JID userJID) {
            if (filterEverything) {
                // This includes all type of packets (including subscription-related presences)
                return true;
            }
            Class packetClass = packet.getClass();
            if (Message.class.equals(packetClass)) {
                return filterMessage;
            }
            else if (Presence.class.equals(packetClass)) {
                Presence.Type presenceType = ((Presence) packet).getType();
                // Only filter presences of type available or unavailable
                // (ignore subscription-related presences)
                if (presenceType == null || presenceType == Presence.Type.unavailable) {
                    // Calculate if packet is being received by the user
                    JID to = packet.getTo();
                    boolean incoming = to != null && to.toBareJID().equals(userJID.toBareJID());
                    if (incoming) {
                        return filterPresence_in;
                    }
                    else {
                        return filterPresence_out;
                    }
                }
            }
            else if (IQ.class.equals(packetClass)) {
                return filterIQ;
            }
            return false;
        }

        /**
         * Type defines if the rule is based on JIDs, roster groups or presence subscription types.
         */
        private static enum Type {
            /**
             * JID being analyzed should belong to a roster group of the list's owner.
             */
            group,
            /**
             * JID being analyzed should have a resource match, domain match or bare JID match.
             */
            jid,
            /**
             * JID being analyzed should belong to a contact present in the owner's roster with
             * the specified subscription status.
             */
            subscription
        }
    }
}
