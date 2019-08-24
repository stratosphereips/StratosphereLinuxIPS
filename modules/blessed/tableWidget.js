class WidgetTable{
    constructor({blessed = {}, contrib = {}, screen = {}, grid = {}}){
        this.blessed = blessed;
        this.contrib = contrib;
        this.screen = screen;
        this.grid = grid;
        this.parameters = {vi:true, scrollbar:true, label:'default', columnWidth : [200], style:{border:{fg:'green'}}};
        this.widget = this.getWidget();
    }

    getWidget(){
        return this.grid.gridObj.set(...this.grid.gridLayout, this.contrib.table, this.parameters);
    }

    
}
module.exports = WidgetTable;
