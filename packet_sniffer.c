#include <gtk/gtk.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

GtkWidget *combo_box;
GtkWidget *text_view;
GtkWidget *start_button;
GtkWidget *stop_button;
pcap_if_t *alldevs;
pcap_t *handle = NULL;
pthread_t sniff_thread;

typedef struct {
    char *text;
} TextUpdateData;

gboolean update_text_buffer(gpointer data) {
    TextUpdateData *ud = (TextUpdateData *)data;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer, &end);
    gtk_text_buffer_insert(buffer, &end, ud->text, -1);
    free(ud->text);
    free(ud);
    return FALSE;
}

void append_text(const char *text) {
    TextUpdateData *ud = malloc(sizeof(TextUpdateData));
    ud->text = strdup(text);
    g_idle_add(update_text_buffer, ud);
}

// -- enable/disable buttons safely on main GTK thread --
gboolean set_button_states(gpointer data) {
    gtk_widget_set_sensitive(start_button, TRUE);
    gtk_widget_set_sensitive(stop_button, FALSE);
    return FALSE;
}

// Callback for each packet
void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    if (!packet) return;

    const struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return;

    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    char info[256];
    snprintf(info, sizeof(info),
             "\n=== Packet Captured ===\nFrom: %s\nTo:   %s\n",
             inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
    append_text(info);

    switch (ip_header->ip_p) {
        case IPPROTO_TCP: append_text("Protocol: TCP\n"); break;
        case IPPROTO_UDP: append_text("Protocol: UDP\n"); break;
        case IPPROTO_ICMP: append_text("Protocol: ICMP\n"); break;
        default:
            snprintf(info, sizeof(info), "Protocol: Other (%d)\n", ip_header->ip_p);
            append_text(info);
    }
}

// Sniffing thread
void *sniff_thread_func(void *arg) {
    pcap_loop(handle, 0, packet_handler, NULL);
    if (handle != NULL) {
        pcap_close(handle);
        handle = NULL;
    }
    append_text("\nSniffing stopped.\n");

    g_idle_add(set_button_states, NULL);
    return NULL;
}

void on_sniff_button_clicked(GtkButton *button, gpointer user_data) {
    const gchar *selected_iface = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo_box));
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!selected_iface) {
        append_text("Please select an interface.\n");
        return;
    }

    handle = pcap_open_live(selected_iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Could not open device %s: %s\n", selected_iface, errbuf);
        append_text(msg);
        return;
    }

    append_text("Sniffing started...\n");
    gtk_widget_set_sensitive(start_button, FALSE);
    gtk_widget_set_sensitive(stop_button, TRUE);

    pthread_create(&sniff_thread, NULL, sniff_thread_func, NULL);
}

void on_stop_button_clicked(GtkButton *button, gpointer user_data) {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Packet Sniffer GUI");
    gtk_window_set_default_size(GTK_WINDOW(window), 600, 400);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    combo_box = gtk_combo_box_text_new();
    start_button = gtk_button_new_with_label("Start Sniffing");
    stop_button = gtk_button_new_with_label("Stop Sniffing");
    gtk_widget_set_sensitive(stop_button, FALSE);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    gtk_container_add(GTK_CONTAINER(scroll), text_view);

    gtk_box_pack_start(GTK_BOX(vbox), combo_box, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), start_button, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), stop_button, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 5);

    gtk_container_add(GTK_CONTAINER(window), vbox);

    // Populate interface list
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_box), dev->name);
    }

    g_signal_connect(start_button, "clicked", G_CALLBACK(on_sniff_button_clicked), NULL);
    g_signal_connect(stop_button, "clicked", G_CALLBACK(on_stop_button_clicked), NULL);

    gtk_widget_show_all(window);
    gtk_main();

    pcap_freealldevs(alldevs);
    return 0;
}