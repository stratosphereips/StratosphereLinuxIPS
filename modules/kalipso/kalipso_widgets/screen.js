// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib } = require("./libraries.js");
const evidence = require('./evidence.js')
const timeline = require('./timeline.js')
const outtuples = require('./outtuples.js')
const intuples = require('./intuples.js')
const ipinfo = require('./ipinfo.js')
const profile_tws = require('./profile_tws.js')

const listtable = require('../lib_widgets/listtable.js')
const gauge = require('../lib_widgets/gauge.js')
const combine = require('./kalipso_connect_listtable_gauge.js')
const listbar = require('../lib_widgets/listbar.js')
const help_lib = require('./help.js')
const profile_evidences = require('./profile_evidences.js')

class screen {
    constructor(redis_database, limit_letter_outtuple) {

        this.redis_database = redis_database
        this.limit_letter_outtuple = limit_letter_outtuple

        this.screen = this.initScreen()
        this.grid = this.initGrid()

        this.tree_widget = undefined
        this.timeline_widget = undefined
        this.evidence_box_widget = undefined
        this.focus_widget = undefined
        this.focus_hotkey = false
        this.combine_listtable_gauge = undefined

        this.mainPage = this.initMain()
        this.ihotkey = this.initIHotkey()
        this.yhotkey = this.initYHotkey()
        this.zhotkey = this.initZHotkey()
        this.edprthotkey = this.initEDRPTHotkey()
        this.helpbar = this.initListBar()
        this.helptable = this.initHelpTable()

        this.activePage = this.mainPage
        this.render()
    }

    /*Initialize the screen*/
    initScreen(){
        return new blessed.screen()
    }

    /*Initialize grid*/
    initGrid(){
    	return new blessed_contrib.grid({
		  rows: 6,
		  cols: 6,
		  screen: this.screen
		});
    }

    /*Initialize help bar on the screen*/
    initHelpTable(){
        const helptable = new help_lib.HelpClass(this.grid, this.redis_database, [0, 0, 5.7, 6,'help'])
        helptable.setHelp()
        helptable.hide()
        return [helptable]
    }

    /*initialize Listbar with hotkeys on the screen*/
    initListBar(){
      return new listbar.ListBarClass(this.grid)
    }

    initEDRPTHotkey(){
      let listtable1 = new listtable.ListTableClass(this.grid, this.redis_database, [0,0,2.8,2])
      listtable1.hide()
      let listtable2 = new listtable.ListTableClass(this.grid, this.redis_database, [2.8,0,2.8,2])
      listtable2.hide()
      let gauge1 = new gauge.GaugeClass(this.grid, [0.3, 2, 2.6, 4])
      gauge1.hide()
      let gauge2 = new gauge.GaugeClass(this.grid,  [3.1, 2, 2.6, 4])
      gauge2.hide()

      this.combine_listtable_gauge = new combine.combineClass(this.grid, this.redis_database, this.screen, listtable1, listtable2, gauge1, gauge2)

      return [listtable1, listtable2, gauge1, gauge2]
    }


    initZHotkey(){
      let profile_evidences_widget = new profile_evidences.ProfileEvidencesClass(this.grid, this.redis_database,this.screen, [0, 0, 5.7, 6,'ProfileEvidence',[30,200], true])
      profile_evidences_widget.widget.hide()
      return [profile_evidences_widget]
    }

    initIHotkey(){
      let outtuples_widget = new outtuples.OutTuplesClass(this.grid, this.redis_database, this.screen, [0,0,5.7,6], this.limit_letter_outtuple)
      outtuples_widget.hide()
      return [outtuples_widget]
    }

    initYHotkey(){
      let intuples_widget = new intuples.InTuplesClass(this.grid, this.redis_database, this.screen, [0,0,5.7,6], this.limit_letter_outtuple)
      intuples_widget.hide()
      return [intuples_widget]
    }

    /* Separate all main page widgets*/
    initMain(){
        this.evidence_box_widget = new evidence.EvidenceClass(this.grid, this.redis_database, this.screen, [4.8,1, 0.9, 5,'Evidence'])
        let ipinfo_widget = new ipinfo.IpInfoClass(this.grid, this.redis_database, this.screen, [0, 1, 0.6, 5,'IPInfo',[30,30,10,10,10,10], false])
        this.timeline_widget = new timeline.TimelineClass(this.grid, this.screen, this.redis_database, [0.6, 1, 4.3, 5,'Timeline',[200], true])
        this.tree_widget = new profile_tws.ProfileTWsClass(this.grid, this.screen, this.redis_database, this.timeline_widget, this.evidence_box_widget, ipinfo_widget)

        this.timeline_widget.on(ipinfo_widget)
        this.tree_widget.getTreeDataFromDatabase()
        this.tree_widget.focus()
        this.tree_widget.on()
        this.tree_widget.widget.style.border.fg = 'magenta'
        this.focus_widget = this.tree_widget
        return [this.tree_widget.widget, ipinfo_widget,  this.evidence_box_widget.widget, this.timeline_widget.widget]
    }


//    /*Display data for SrcPortsClient established and not established*/
    e_hotkey_routine(){
      this.activePage.forEach(item => item.hide());
      this.edprthotkey.forEach(item => item.show());

      this.combine_listtable_gauge.operate(
        this.tree_widget.current_ip,
        this.tree_widget.current_tw,
        'SrcPortsClientTCPEstablished','SrcPortsClientUDPEstablished',
        'SrcPortsClientTCPNotEstablished', 'SrcPortsClientUDPNotEstablished',
        ['estSrcPortClient', 'totalflows', 'totalpkts','totalbytes'],
        ['NotEstSrcPortClient', 'totalflows', 'totalpkts','totalbytes']
      )
    }

    /*Display data for dstIPsClient established and not established*/
    d_hotkey_routine(){
      this.activePage.forEach(item => item.hide());
      this.edprthotkey.forEach(item => item.show());

      this.combine_listtable_gauge.operate(
        this.tree_widget.current_ip,
        this.tree_widget.current_tw,
        'DstIPsClientTCPEstablished','DstIPsClientUDPEstablished',
        'DstIPsClientTCPNotEstablished', 'DstIPsClientUDPNotEstablished',
        ['estDstIPsClient', 'totalflows', 'totalpkts','totalbytes'],
        ['NotEstDstIPsClient', 'totalflows', 'totalpkts','totalbytes']
      )
    }

    /*Display data for dstPortsClient established and not established*/
    t_hotkey_routine(){
      this.activePage.forEach(item => item.hide());
      this.edprthotkey.forEach(item => item.show());

      this.combine_listtable_gauge.operate_IPs(
        this.tree_widget.current_ip,
        this.tree_widget.current_tw,
        'DstPortsClientTCPEstablished','DstPortsClientUDPEstablished',
        'DstPortsClientTCPNotEstablished', 'DstPortsClientUDPNotEstablished',
        ['estDstPortClient',  'IP','Number of connections'],
        ['NotEstDstPortClient',  'IP','Number of packets']
      )
    }

    /*Display data for dstPortsServer established and not established*/
    r_hotkey_routine(){

      this.activePage.forEach(item => item.hide());
      this.edprthotkey.forEach(item => item.show());

      this.combine_listtable_gauge.operate(
        this.tree_widget.current_ip,
        this.tree_widget.current_tw,
        'DstPortsServerTCPEstablished','DstPortsServerUDPEstablished',
        'DstPortsServerTCPNotEstablished', 'DstPortsServerUDPNotEstablished',
        ['estDstPortServer', 'totalflows', 'totalpkts','totalbytes'],
        ['NotEstDstPortServer', 'totalflows', 'totalpkts','totalbytes'])
    }

    /*Display data for DstPortsClient established and not established*/
    p_hotkey_routine(){
       this.activePage.forEach(item => item.hide());
       this.edprthotkey.forEach(item => item.show());

      this.combine_listtable_gauge.operate(
        this.tree_widget.current_ip,
        this.tree_widget.current_tw,
        'DstPortsClientTCPEstablished','DstPortsClientUDPEstablished',
        'DstPortsClientTCPNotEstablished', 'DstPortsClientUDPNotEstablished',
        ['estDstPortClient',  'totalflows','totalpkts','totalbytes'],
        ['NotEstDstPortClient',  'totalflows','totalpkts','totalbytes']
      )
    }

    /*Function to fill and prepare the widget with out tuples*/
    z_hotkey_routine(){
      this.activePage.forEach(item => item.hide());
      this.zhotkey.forEach(item => item.show());

      this.zhotkey[0].setEvidencesInProfile(this.tree_widget.current_ip)
      this.zhotkey[0].focus()
      this.render()
    }

    i_hotkey_routine(){
      this.activePage.forEach(item => item.hide());
      this.ihotkey.forEach(item => item.show());

      this.ihotkey[0].setOutTuples(this.tree_widget.current_ip, this.tree_widget.current_tw)
      this.ihotkey[0].focus()
      this.render()
    }

    /*Function to fill and prepare the widget with in tuples*/
    y_hotkey_routine(){
      this.activePage.forEach(item => item.hide());
      this.yhotkey.forEach(item => item.show());

      this.yhotkey[0].setInTuples(this.tree_widget.current_ip, this.tree_widget.current_tw)
      this.yhotkey[0].focus()
      this.render()
    }


    /*Function to update tree widget, i.e profiles and timewindows*/
    o_hotkey_routine(){
      this.tree_widget.getTreeDataFromDatabase()
      this.render()
    }

    /*Function to display help hotkey*/
    h_hotkey_routine(){
      this.activePage.forEach(item => item.hide());
      this.helptable[0].show()
      this.render()
    }


    /*Function to go back from the hotkeys to main page of the interface*/
    main_page_routine(){
      this.activePage.forEach(item => item.hide());
      this.mainPage.forEach(item => item.show());
      this.focus_widget.focus()
      this.render()
    }

    /*Function to update interface every two minutes*/
    update_interface(){
        setInterval(this.o_hotkey_routine.bind(this), 120000)
    }

    /*Function to monitor all keypresses happening on the screen*/
    registerEvents(){
      this.screen.on('keypress', (ch, key)=>{
        if(key.name == 'tab' && this.activePage == this.mainPage){
          if(this.focus_widget == this.tree_widget){
            this.focus_widget = this.timeline_widget
            this.tree_widget.widget.style.border.fg = 'blue'
            this.timeline_widget.widget.style.border.fg='magenta'
            this.timeline_widget.widget.focus();}
          else if(this.focus_widget == this.timeline_widget){
            this.timeline_widget.widget.style.border.fg='blue'
            this.focus_widget = this.evidence_box_widget
            this.evidence_box_widget.widget.focus()}
          else if (this.focus_widget == this.evidence_box_widget){
            this.focus_widget = this.tree_widget
            this.tree_widget.widget.style.border.fg = 'magenta'
            this.tree_widget.focus();}
          this.render();
        }
        else if(key.name == 'q' || key.name == "C-c"){
            return process.exit(0)
        }
        else if(key.name == 'escape'){
          this.helpbar.selectTab(0)
          this.main_page_routine()
          this.activePage = this.mainPage
        }
        else if(key.name == 'p'){
          this.helpbar.selectTab(4)
          this.p_hotkey_routine()
          this.activePage = this.edprthotkey
        }
        else if(key.name == 'r'){
          this.helpbar.selectTab(3)
          this.r_hotkey_routine()
          this.activePage = this.edprthotkey
        }
        else if(key.name == 'd'){
          this.helpbar.selectTab(2)
          this.d_hotkey_routine()
          this.activePage = this.edprthotkey
        }
        else if(key.name == 't'){
          this.helpbar.selectTab(5)
          this.t_hotkey_routine()
          this.activePage = this.edprthotkey
        }
        else if(key.name == 'e'){
          this.helpbar.selectTab(1)
          this.e_hotkey_routine()
          this.activePage = this.edprthotkey
        }
        else if(key.name == 'i'){
          this.helpbar.selectTab(6)
          this.i_hotkey_routine()
          this.activePage = this.ihotkey
        }
        else if(key.name == 'z'){
          this.helpbar.selectTab(8)
          this.z_hotkey_routine()
          this.activePage = this.zhotkey
        }
        else if(key.name == 'y'){
          this.helpbar.selectTab(7)
          this.y_hotkey_routine()
          this.activePage = this.yhotkey
        }
        else if(key.name == 'o'){
          this.helpbar.selectTab(0)
          this.o_hotkey_routine()
        }
        else if(key.name == 'h'){
          this.helpbar.selectTab(12)
          this.h_hotkey_routine()
          this.activePage = this.helptable
        }
        else if(this.activePage == this.edprthotkey && (key.name == 'down' || key.name == 'j')){
            this.combine_listtable_gauge.down()
        }
        else if(this.activePage == this.edprthotkey && (key.name == 'up' || key.name == 'k')){
            this.combine_listtable_gauge.up()
        }
        else if(key.name == 'tab' && this.activePage == this.edprthotkey){
            this.combine_listtable_gauge.changeFocus()
        }

        this.render()
      })

    }

    /*Render the screen*/
    render(){
    	this.screen.render()
    }

}

module.exports = screen;
