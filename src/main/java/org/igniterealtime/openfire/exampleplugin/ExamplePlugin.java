package org.igniterealtime.openfire.exampleplugin;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;

import java.io.File;

public class ExamplePlugin implements Plugin {
    private XMPPServer server;

    @Override
    public void initializePlugin(PluginManager manager, File pluginDirectory) {
        server = XMPPServer.getInstance();
        System.out.println("HelloWorldPlugin----start");
        System.out.println(server.getServerInfo());
    }

    @Override
    public void destroyPlugin() {
        System.out.println("HelloWorldPlugin----destroy");
    }

}
